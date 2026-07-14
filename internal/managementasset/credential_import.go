package managementasset

import _ "embed"

//go:embed credential_import.html
var credentialImportHTML []byte

// CredentialImportHTML returns the embedded credential import control panel.
func CredentialImportHTML() []byte {
	return credentialImportHTML
}
