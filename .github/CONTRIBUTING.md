# Contributing to k8scan

Thank you for your interest in contributing to k8scan! This document provides guidelines and instructions for contributing.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in Issues
2. Create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Go version, k8s version)

### Suggesting Features

1. Open an issue with the "enhancement" label
2. Describe the feature and use case
3. Explain why it would be valuable

### Pull Requests

1. **Fork** the repository
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/my-feature
   ```
3. **Make your changes**:
   - Write clear, idiomatic Go code
   - Follow existing code style
   - Add tests if applicable
4. **Test your changes**:
   ```bash
   go test ./...
   ```
5. **Commit** with clear messages:
   ```bash
   git commit -m "Add feature: description"
   ```
6. **Push** to your fork:
   ```bash
   git push origin feature/my-feature
   ```
7. **Open a Pull Request**

## Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/k8scan.git
cd k8scan

# Download dependencies
go mod tidy

# Build the binary
go build -o bin/k8scan ./cmd/k8scan

# Or use the Makefile
make build

# Run locally
make run
```

**Requirements:**
- Go 1.24+
- Access to a Kubernetes cluster (or use `--kubeconfig` to point to a local cluster like kind/minikube)

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Use meaningful variable and function names
- Keep functions focused and small
- Run the linter before submitting:
  ```bash
  golangci-lint run ./...
  # or
  make lint
  ```

### Example:

```go
// ScanPods checks pods for security misconfigurations.
func ScanPods(pods []corev1.Pod) []Finding {
    var findings []Finding
    for _, pod := range pods {
        // scan logic
    }
    return findings
}
```

## Testing

- Write tests for new features
- Ensure existing tests pass before submitting:
  ```bash
  go test ./... -race -count=1
  # or
  make test
  ```
- Test with different Kubernetes versions if possible

## Documentation

- Update `README.md` for user-facing changes
- Add comments for exported functions and types
- Update examples if behavior changes

## Adding New Security Checks

1. Create your scanner under `internal/modules/`
2. Implement the scanner logic and register it
3. Add tests covering both vulnerable and clean cases
4. Document the check in `README.md`

### Example Structure:

```go
// internal/modules/my_check.go
package modules

import (
    "github.com/alperenkeskin/k8scan/internal/findings"
    corev1 "k8s.io/api/core/v1"
)

func CheckMyVulnerability(pods []corev1.Pod) []findings.Finding {
    var result []findings.Finding
    for _, pod := range pods {
        // detection logic
    }
    return result
}
```

## Useful Make Targets

| Command        | Description                        |
|----------------|------------------------------------|
| `make build`   | Build the binary to `bin/k8scan`   |
| `make test`    | Run all tests with race detector   |
| `make lint`    | Run golangci-lint                  |
| `make tidy`    | Run `go mod tidy`                  |
| `make clean`   | Remove build artifacts             |
| `make docker`  | Build Docker image                 |
| `make release` | Cross-compile for all platforms    |

## Questions?

Feel free to open an issue for any questions about contributing!

Thank you for making k8scan better!
