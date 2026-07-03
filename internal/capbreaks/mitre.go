package capbreaks

import "github.com/alperenkesk/k8scan/internal/core"

// MITRE ATT&CK for Containers technique sets per CB rule.

var mitreCB001 = []core.MITRETechnique{
	{ID: "T1611", Name: "Escape to Host", Tactic: "Privilege Escalation"},
	{ID: "T1543", Name: "Create or Modify System Process", Tactic: "Persistence"},
}

var mitreCB002 = []core.MITRETechnique{
	{ID: "T1484", Name: "Domain Policy Modification", Tactic: "Privilege Escalation"},
	{ID: "T1078", Name: "Valid Accounts", Tactic: "Defense Evasion"},
}

var mitreCB003 = []core.MITRETechnique{
	{ID: "T1548", Name: "Abuse Elevation Control Mechanism", Tactic: "Privilege Escalation"},
	{ID: "T1078", Name: "Valid Accounts", Tactic: "Defense Evasion"},
}

var mitreCB004 = []core.MITRETechnique{
	{ID: "T1528", Name: "Steal Application Access Token", Tactic: "Credential Access"},
	{ID: "T1078.004", Name: "Cloud Accounts", Tactic: "Defense Evasion"},
}

var mitreCB005 = []core.MITRETechnique{
	{ID: "T1562", Name: "Impair Defenses", Tactic: "Defense Evasion"},
	{ID: "T1610", Name: "Deploy Container", Tactic: "Execution"},
}

var mitreCB006 = []core.MITRETechnique{
	{ID: "T1611", Name: "Escape to Host", Tactic: "Privilege Escalation"},
	{ID: "T1610", Name: "Deploy Container", Tactic: "Execution"},
}

var mitreCB007 = []core.MITRETechnique{
	{ID: "T1552", Name: "Unsecured Credentials", Tactic: "Credential Access"},
	{ID: "T1555", Name: "Credentials from Password Stores", Tactic: "Credential Access"},
}

var mitreCB008 = []core.MITRETechnique{
	{ID: "T1195", Name: "Supply Chain Compromise", Tactic: "Initial Access"},
	{ID: "T1078", Name: "Valid Accounts", Tactic: "Defense Evasion"},
}

var mitreCB009 = []core.MITRETechnique{
	{ID: "T1484", Name: "Domain Policy Modification", Tactic: "Privilege Escalation"},
	{ID: "T1078", Name: "Valid Accounts", Tactic: "Persistence"},
}

var mitreCB010 = []core.MITRETechnique{
	{ID: "T1552.005", Name: "Cloud Instance Metadata API", Tactic: "Credential Access"},
	{ID: "T1078.004", Name: "Cloud Accounts", Tactic: "Defense Evasion"},
}
