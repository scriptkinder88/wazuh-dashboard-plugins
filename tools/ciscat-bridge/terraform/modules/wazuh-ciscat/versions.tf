terraform {
  # 1.9: variable validations that refer to other variables (baseline_prefix).
  # No provider is needed: the module works over SSH, and the caller passes the
  # secrets (for example read from Vault).
  required_version = ">= 1.9.0"
}
