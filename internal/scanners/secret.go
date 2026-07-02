package scanners

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/alperenkeskin/k8scan/internal/core"
	"github.com/alperenkeskin/k8scan/internal/utils"
)

// SecretScanner scans Kubernetes Secret objects for weak/exposed credentials.
type SecretScanner struct{}

func (SecretScanner) Name() string { return "Secret Security" }

func (SecretScanner) Scan(ctx context.Context, client core.KubeReader) ([]*core.Finding, error) {
	secrets, err := client.GetAllSecrets(ctx)
	if err != nil {
		return nil, err
	}

	var findings []*core.Finding
	for _, secret := range secrets {
		findings = append(findings, checkSecret(secret)...)
	}
	return findings, nil
}

// ConfigMapScanner scans ConfigMaps for accidentally stored sensitive data.
type ConfigMapScanner struct{}

func (ConfigMapScanner) Name() string { return "ConfigMap Security" }

func (ConfigMapScanner) Scan(ctx context.Context, client core.KubeReader) ([]*core.Finding, error) {
	configmaps, err := client.GetAllConfigMaps(ctx)
	if err != nil {
		return nil, err
	}

	var findings []*core.Finding
	for _, cm := range configmaps {
		findings = append(findings, checkConfigMap(cm)...)
	}
	return findings, nil
}

// ─── Secret patterns ──────────────────────────────────────────────────────────

type secretPattern struct {
	re       *regexp.Regexp
	title    string
	severity core.Severity
}

var secretPatterns = []secretPattern{
	{regexp.MustCompile(`(?i)(AKIA|AGPA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`), "Potential Aws Access Key Found", core.SeverityCritical},
	{regexp.MustCompile(`(?i)aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key[\s]*[=:]+\s*[A-Za-z0-9/+=]{40}`), "Potential Aws Secret Key Found", core.SeverityCritical},
	{regexp.MustCompile(`(?i)ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}`), "Potential Github Token Found", core.SeverityHigh},
	{regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`), "Potential Private Key Found", core.SeverityCritical},
	{regexp.MustCompile(`(?i)xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}`), "Potential Slack Token Found", core.SeverityHigh},
	{regexp.MustCompile(`(?i)https://hooks\.slack\.com/services/[A-Za-z0-9/]+`), "Potential Slack Webhook Found", core.SeverityHigh},
	{regexp.MustCompile(`(?i)AIza[0-9A-Za-z\-_]{35}`), "Potential Google Api Found", core.SeverityHigh},
	// JWT regex is intentionally LOW confidence — the base64url pattern is very broad
	// and fires on many non-JWT values. It is only emitted when the key name also
	// suggests a token (see scanValueForSecrets). Kept for signal value despite noise.
	{regexp.MustCompile(`(?i)eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]+`), "Potential Jwt Token Found", core.SeverityMedium},
	{regexp.MustCompile(`(?i)(password|passwd|pwd|secret|api[_-]?key|token|auth)[_\s]*[=:]+\s*[^\s]{8,}`), "Potential Generic Secret Found", core.SeverityMedium},
	{regexp.MustCompile(`(?i)(mysql|postgres|mongodb|redis):\/\/[^:\s]+:[^@\s]+@`), "Potential Database Credentials Found", core.SeverityHigh},
}


var highConfidenceSecretTitles = utils.NewStringSet(
	"Potential Aws Access Key Found",
	"Potential Aws Secret Key Found",
	"Potential Private Key Found",
	"Potential Github Token Found",
)

var sensitiveSecretKeys = []string{
	"password", "passwd", "pwd", "secret", "token", "key", "api",
	"auth", "credential", "cred", "private", "cert",
}

var systemSecretPrefixes = []string{
	"kubernetes.io/service-account-token",
	"bootstrap.kubernetes.io",
}

// ─── Secret checking ──────────────────────────────────────────────────────────

func checkSecret(secret corev1.Secret) []*core.Finding {
	var findings []*core.Finding

	if isSystemSecret(secret) {
		return nil
	}

	if secret.Type == corev1.SecretTypeServiceAccountToken {
		return nil
	}

	ns := secret.Namespace
	name := secret.Name

	if isEffectivelyEmpty(secret) {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityLow,
			Category:     "secrets",
			Title:        "Empty Secret",
			Description:  "Secret has no data. May indicate misconfigured or leftover resource.",
			ResourceType: "Secret",
			ResourceName: name,
			Namespace:    ns,
			Remediation:  "Remove unused secrets or populate with required data.",
		})
		return findings
	}

	if secret.Type == "kubernetes.io/basic-auth" {
		pass := string(secret.Data["password"])
		if pass == "" {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityCritical,
				Category:     "secrets",
				Title:        "Basic Auth Secret Has Empty Password",
				Description:  fmt.Sprintf("Secret '%s' (type: kubernetes.io/basic-auth) has an empty password field — any user can authenticate with just the username.", name),
				ResourceType: "Secret", ResourceName: name, Namespace: ns,
				Remediation: "Set a strong, randomly generated password in the 'password' field of the basic-auth secret.",
			})
		}
	}

	if secret.Type == corev1.SecretTypeTLS {
		if certPEM, ok := secret.Data["tls.crt"]; ok {
			findings = append(findings, checkTLSCertExpiry(certPEM, name, ns)...)
		}
	}

	if secret.Type == corev1.SecretTypeDockerConfigJson {
		if raw, ok := secret.Data[".dockerconfigjson"]; ok {
			findings = append(findings, checkDockerConfigHTTP(raw, name, ns)...)
		}
	}

	age := time.Since(secret.CreationTimestamp.Time)
	if age > 365*24*time.Hour && isSensitiveSecret(secret) {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityLow,
			Category:     "secrets",
			Title:        "Secret Not Rotated in Over a Year",
			Description:  fmt.Sprintf("Secret '%s' was created %.0f days ago and appears not to have been rotated — stale credentials increase the blast radius of a leak.", name, age.Hours()/24),
			ResourceType: "Secret", ResourceName: name, Namespace: ns,
			Remediation: "Implement a secret rotation policy. Use external secret managers (HashiCorp Vault, AWS Secrets Manager) with automatic rotation.",
			Metadata:    map[string]any{"age_days": int(age.Hours() / 24)},
		})
	}

	allValues := collectSecretValues(secret)
	for _, entry := range allValues {
		findings = append(findings, scanValueForSecrets(entry.key, entry.value, "Secret", name, ns)...)
	}

	for key, val := range secret.Data {
		decoded := string(val)
		if isSensitiveKey(key) && len(decoded) > 0 && len(decoded) < 8 {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityMedium,
				Category:     "secrets",
				Title:        "Weak Secret Detected",
				Description:  "Secret value for key '" + key + "' is very short (< 8 characters), indicating a weak credential.",
				ResourceType: "Secret",
				ResourceName: name,
				Namespace:    ns,
				Remediation:  "Use strong, randomly generated secrets (at least 16 characters).",
			})
		}
	}

	return findings
}

// isSensitiveSecret returns true for secrets that contain credentials worth rotating.
func isSensitiveSecret(s corev1.Secret) bool {
	switch s.Type {
	case corev1.SecretTypeTLS, corev1.SecretTypeDockerConfigJson,
		corev1.SecretTypeBasicAuth, corev1.SecretTypeSSHAuth:
		return true
	}
	for k := range s.Data {
		if isSensitiveKey(k) {
			return true
		}
	}
	return false
}

func checkTLSCertExpiry(certPEM []byte, name, ns string) []*core.Finding {
	var findings []*core.Finding
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	now := time.Now()
	if cert.NotAfter.Before(now) {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityHigh,
			Category:     "secrets",
			Title:        "TLS Certificate Expired",
			Description:  fmt.Sprintf("Secret '%s' (namespace: %s) contains a TLS certificate that expired on %s — HTTPS connections will fail with certificate errors.", name, ns, cert.NotAfter.Format("2006-01-02")),
			ResourceType: "Secret", ResourceName: name, Namespace: ns,
			Remediation: "Renew the TLS certificate immediately. Use cert-manager to automate certificate lifecycle management.",
			Metadata:    map[string]any{"expired_at": cert.NotAfter.Format(time.RFC3339), "subject": cert.Subject.CommonName},
		})
	} else if cert.NotAfter.Before(now.Add(30 * 24 * time.Hour)) {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityMedium,
			Category:     "secrets",
			Title:        "TLS Certificate Expiring Soon",
			Description:  fmt.Sprintf("Secret '%s' (namespace: %s) contains a TLS certificate expiring on %s (within 30 days).", name, ns, cert.NotAfter.Format("2006-01-02")),
			ResourceType: "Secret", ResourceName: name, Namespace: ns,
			Remediation: "Renew the TLS certificate before it expires. Use cert-manager to automate certificate renewal.",
			Metadata:    map[string]any{"expires_at": cert.NotAfter.Format(time.RFC3339), "subject": cert.Subject.CommonName},
		})
	}
	return findings
}

type dockerConfig struct {
	Auths map[string]struct {
		Auth string `json:"auth"`
	} `json:"auths"`
}

func checkDockerConfigHTTP(raw []byte, name, ns string) []*core.Finding {
	var cfg dockerConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil
	}
	var findings []*core.Finding
	for registry := range cfg.Auths {
		if strings.HasPrefix(registry, "http://") {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityHigh,
				Category:     "secrets",
				Title:        "Docker Registry Using Insecure HTTP",
				Description:  fmt.Sprintf("Secret '%s' (namespace: %s) configures registry '%s' over HTTP — credentials and image layers are transmitted in plaintext.", name, ns, registry),
				ResourceType: "Secret", ResourceName: name, Namespace: ns,
				Remediation: "Switch the registry to HTTPS. Never use HTTP registries in production — image pulls and credential exchanges are interceptable.",
				Metadata:    map[string]any{"registry": registry},
			})
		}
	}
	return findings
}

type keyValue struct {
	key   string
	value string
}

func collectSecretValues(secret corev1.Secret) []keyValue {
	var entries []keyValue
	for k, v := range secret.Data {
		entries = append(entries, keyValue{k, string(v)})
	}
	for k, v := range secret.StringData {
		entries = append(entries, keyValue{k, v})
	}
	return entries
}

// isEffectivelyEmpty returns true for secrets with no data or only empty-value keys.
// A live secret always has empty stringData (write-only field), so we only inspect Data.
func isEffectivelyEmpty(secret corev1.Secret) bool {
	if len(secret.StringData) > 0 {
		return false
	}
	for _, v := range secret.Data {
		if len(v) > 0 {
			return false
		}
	}
	return true
}

func isSystemSecret(secret corev1.Secret) bool {
	// Skip secrets in system namespaces entirely — operators and Kubernetes itself
	// store many Opaque secrets there that are not user-managed credentials.
	if utils.IsSystemNamespace(secret.Namespace) {
		return true
	}
	for _, prefix := range systemSecretPrefixes {
		if strings.HasPrefix(string(secret.Type), prefix) {
			return true
		}
	}
	if _, ok := secret.Annotations["kubernetes.io/service-account.name"]; ok {
		return true
	}
	return false
}


func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	for _, s := range sensitiveSecretKeys {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

func scanValueForSecrets(key, value, resourceType, resourceName, namespace string) []*core.Finding {
	if len(value) < 8 {
		return nil
	}
	if isPlaceholder(value) {
		return nil
	}

	var findings []*core.Finding
	seen := utils.NewStringSet()

	for _, p := range secretPatterns {
		if p.re.MatchString(value) {
			if seen.Has(p.title) {
				continue
			}

			// JWT pattern is very broad (matches any base64url.base64url.base64url).
			// Only emit it when the key name also hints at a token/jwt/auth value,
			// otherwise it fires on random binary data and produces too much noise.
			if p.title == "Potential Jwt Token Found" {
				lowerKey := strings.ToLower(key)
				jwtKeyHints := []string{"token", "jwt", "auth", "bearer", "access", "id_token", "refresh"}
				hasHint := false
				for _, hint := range jwtKeyHints {
					if strings.Contains(lowerKey, hint) {
						hasHint = true
						break
					}
				}
				if !hasHint {
					continue
				}
			}

			seen.Add(p.title)

			confidence := core.ConfidenceHigh
			if !highConfidenceSecretTitles.Has(p.title) {
				confidence = core.ConfidenceMedium
			}
			// JWT is explicitly lower confidence regardless of key hints.
			if p.title == "Potential Jwt Token Found" {
				confidence = core.ConfidenceLow
			}

			findings = append(findings, &core.Finding{
				Severity:     p.severity,
				Category:     "secrets",
				Title:        p.title,
				Description:  "Potential secret value found in key '" + key + "' of " + resourceType + " " + resourceName,
				ResourceType: resourceType,
				ResourceName: resourceName,
				Namespace:    namespace,
				Remediation:  "Store secrets in dedicated secret management systems (HashiCorp Vault, AWS Secrets Manager). Rotate any exposed credentials immediately.",
				Confidence:   confidence,
			})
		}
	}

	return findings
}

// ─── ConfigMap checking ───────────────────────────────────────────────────────

var configMapSensitiveKeys = []string{
	"password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
	"api-key", "private_key", "privatekey", "private-key", "auth", "credential",
	"aws_access_key", "aws_secret", "database_url", "db_password",
}

func checkConfigMap(cm corev1.ConfigMap) []*core.Finding {
	if isSystemConfigMap(cm) {
		return nil
	}

	ns := cm.Namespace
	name := cm.Name
	var findings []*core.Finding

	for key, value := range cm.Data {
		if len(value) < 8 || isPlaceholder(value) {
			continue
		}

		lowerKey := strings.ToLower(key)
		isSensKey := false
		for _, s := range configMapSensitiveKeys {
			if strings.Contains(lowerKey, s) {
				isSensKey = true
				break
			}
		}

		patternFindings := scanValueForSecrets(key, value, "ConfigMap", name, ns)
		if len(patternFindings) > 0 {
			for _, f := range patternFindings {
				f.Title = "Sensitive Data in ConfigMap"
				f.Description = "Potential secret pattern matched in ConfigMap key '" + key + "'"
			}
			findings = append(findings, patternFindings...)
			continue
		}

		if isSensKey {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityMedium,
				Category:     "secrets",
				Title:        "Sensitive Data in ConfigMap",
				Description:  "ConfigMap key '" + key + "' has a name suggesting it contains sensitive data. ConfigMaps are not encrypted at rest.",
				ResourceType: "ConfigMap",
				ResourceName: name,
				Namespace:    ns,
				Remediation:  "Move sensitive values to Kubernetes Secrets (or external secret manager). ConfigMaps are stored in plaintext in etcd.",
				Confidence:   core.ConfidenceMedium,
			})
		}

		if looksBase64Encoded(value) && len(value) >= 20 {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityHigh,
				Category:     "secrets",
				Title:        "Base64-Encoded Value in ConfigMap",
				Description:  "ConfigMap key '" + key + "' contains a value that appears to be base64-encoded. ConfigMaps are not encrypted — base64 is not encryption, just encoding. Anyone with ConfigMap read access can decode it.",
				ResourceType: "ConfigMap",
				ResourceName: name,
				Namespace:    ns,
				Remediation:  "Move sensitive data to Kubernetes Secrets (encrypted at rest when etcd encryption is enabled) or an external secret manager.",
				Confidence:   core.ConfidenceMedium,
			})
		}
	}

	return findings
}

// looksBase64Encoded returns true when the string appears to be valid base64
// with sufficient entropy to be meaningful (not just a short word or number).
func looksBase64Encoded(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 20 {
		return false
	}
	// Must only contain base64 alphabet characters
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
			return false
		}
	}
	// Attempt decode and check it produces non-trivial binary/text content
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return false
	}
	// Decoded must be non-empty and longer than the threshold
	return len(decoded) >= 10
}

var systemConfigMapNamePrefixes = []string{
	"kube-", "istio-", "calico-", "weave-", "flannel-", "cilium-",
	"coredns", "aws-", "gke-", "aks-", "cert-manager",
}

var systemConfigMapNamespaces = utils.NewStringSet(
	"kube-system", "kube-public", "kube-node-lease",
	"monitoring", "logging", "cert-manager", "istio-system",
)

func isSystemConfigMap(cm corev1.ConfigMap) bool {
	if systemConfigMapNamespaces.Has(cm.Namespace) {
		return true
	}
	lowerName := strings.ToLower(cm.Name)
	for _, prefix := range systemConfigMapNamePrefixes {
		if strings.HasPrefix(lowerName, prefix) {
			return true
		}
	}
	if _, ok := cm.Labels["helm.sh/chart"]; ok {
		return true
	}
	return false
}

func isPlaceholder(v string) bool {
	return strings.HasPrefix(v, "{{") ||
		strings.HasPrefix(v, "$(") ||
		v == "changeme" || v == "CHANGEME" ||
		v == "placeholder" || v == "PLACEHOLDER" ||
		v == "TODO" || v == "todo" ||
		(strings.HasPrefix(v, "<") && strings.HasSuffix(v, ">"))
}

var _ core.Scanner = SecretScanner{}
var _ core.Scanner = ConfigMapScanner{}
