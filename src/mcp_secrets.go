package apm

// mcpSecretArgs are the MCP write-tool arguments that carry secrets. Approval
// prompts show them masked, never their values.
var mcpSecretArgs = map[string]bool{
	"password": true, "secret": true, "key": true, "token_val": true, "cvv": true,
	"secret_key": true, "access_key": true, "serial_key": true, "content": true,
	"id_number": true, "details": true, "codes": true, "env_vars": true, "webhook": true,
}

// IsMCPSecretArg reports whether an MCP tool argument holds a secret.
func IsMCPSecretArg(name string) bool { return mcpSecretArgs[name] }
