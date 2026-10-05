variable "wazuh_major" {
  type    = number
  default = 4
}

variable "master_host" {
  description = "Wazuh master address."
  type        = string
}

variable "dashboard_host" {
  description = "Wazuh dashboard address, when it is not the master."
  type        = string
  default     = null
}

variable "ssh_user" {
  description = "SSH user (root, or a user with passwordless sudo). The key comes from ssh-agent."
  type        = string
  default     = "root"
}

variable "installer_path" {
  description = "ciscat-bridge-install-<version>.sh from the bridge build."
  type        = string
}

variable "installer_sha256" {
  description = "Content of the matching .sha256 file (first field)."
  type        = string
}

variable "plugin_path" {
  description = "Plugin zip from the dashboard build, or null to leave the plugin as it is."
  type        = string
  default     = null
}

variable "plugin_sha256" {
  type    = string
  default = null
}

variable "benchmarks_dir" {
  description = "Local copy of the licensed CIS benchmarks, or null."
  type        = string
  default     = null
}

variable "vault_mount" {
  description = "KV v2 mount holding the Wazuh secrets."
  type        = string
  default     = "secret"
}

variable "vault_secret" {
  description = "Secret with the keys api_user, api_password and, on Wazuh 5.0, indexer_url, indexer_user, indexer_password, indexer_ca."
  type        = string
}
