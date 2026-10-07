variable "wazuh_major" {
  description = "Wazuh major version of the hosts: 4 (4.14.x). Wazuh 5.0 is not supported yet."
  type        = number
  validation {
    condition     = var.wazuh_major == 4
    error_message = "wazuh_major must be 4: Wazuh 5.0 is not supported yet (the bridge installer has no indexer options)."
  }
}

variable "master" {
  description = "SSH connection to the Wazuh master (cluster master or standalone manager). A user other than root needs passwordless sudo."
  type = object({
    host         = string
    user         = optional(string, "root")
    port         = optional(number, 22)
    bastion_host = optional(string)
    bastion_user = optional(string)
  })
}

variable "dashboard" {
  description = "SSH connection to the Wazuh dashboard host, when it is not the master. Null: the plugin is installed on the master host."
  type = object({
    host         = string
    user         = optional(string, "root")
    port         = optional(number, 22)
    bastion_host = optional(string)
    bastion_user = optional(string)
  })
  default = null
}

variable "ssh_private_key" {
  description = "SSH private key (PEM). Null: the running ssh-agent is used."
  type        = string
  default     = null
  sensitive   = true
}

variable "installer" {
  description = "CIS-CAT bridge installer (ciscat-bridge-install-<version>.sh) on the machine running Terraform, and its SHA-256 (from the .sha256 file). Changing them upgrades the bridge."
  type = object({
    path   = string
    sha256 = string
  })
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.installer.sha256))
    error_message = "installer.sha256 must be 64 lowercase hex characters."
  }
}

variable "plugin" {
  description = "Wazuh dashboard plugin zip (as downloaded from the build, the installer opens GitHub's wrapper) and its SHA-256. Null: the plugin is left as it is."
  type = object({
    path   = string
    sha256 = string
  })
  default = null
  validation {
    condition     = var.plugin == null || can(regex("^[0-9a-f]{64}$", var.plugin.sha256))
    error_message = "plugin.sha256 must be 64 lowercase hex characters."
  }
}

variable "api_user" {
  description = "Wazuh server API user of the bridge."
  type        = string
  default     = "wazuh"
  validation {
    condition     = can(regex("^[A-Za-z0-9._-]{1,64}$", var.api_user))
    error_message = "api_user: letters, digits, '.', '_' and '-' only."
  }
}

variable "api_password" {
  description = "Password of api_user. Written to a root-only file on the master, never on a command line."
  type        = string
  sensitive   = true
}

variable "indexer" {
  description = "Wazuh 5.0 only: indexer the bridge writes its data to (URL, user, PEM CA certificate)."
  type = object({
    url    = string
    user   = string
    ca_pem = optional(string)
  })
  default = null
  validation {
    condition     = var.indexer == null || (can(regex("^https://[^'\\s]+$", var.indexer.url)) && can(regex("^[A-Za-z0-9._-]{1,64}$", var.indexer.user)))
    error_message = "indexer.url must be an https URL and indexer.user letters, digits, '.', '_' and '-'."
  }
}

variable "indexer_password" {
  description = "Wazuh 5.0 only: password of indexer.user."
  type        = string
  default     = null
  sensitive   = true
}

variable "benchmarks_dir" {
  description = "Local folder with the licensed CIS benchmarks (XCCDF, OVAL, CPE), copied to /opt/ciscat/benchmarks. Null: the folder on the master is left as it is."
  type        = string
  default     = null
}

variable "exclusions_seed" {
  description = "CIS-CAT exclusions CSV per OS key, imported only by the first install (afterwards exclusions are managed in the dashboard)."
  type        = map(string)
  default     = {}
}

variable "apply_policies" {
  description = "Run the bridge apply after each install (publishes the policies to the agents)."
  type        = bool
  default     = false
}

variable "baseline_prefix" {
  description = "Prefix of the groups owned by Terraform. Every other group belongs to the dashboard."
  type        = string
  default     = "baseline-"
}

variable "baseline_groups" {
  description = <<-EOT
    Groups owned by Terraform: their whole agent.conf is written from here, and the listed agents
    are added to them. Rules carry the same audit comment as the dashboard ones (reason, ticket,
    owner), so the FIM tab shows them.
  EOT
  type = map(object({
    os      = optional(string)
    agents  = optional(list(string), [])
    options = optional(map(string), {})
    fim = list(object({
      kind   = string
      path   = string
      attrs  = optional(map(string), {})
      reason = string
      ticket = optional(string, "")
      owner  = optional(string, "")
      since  = optional(string, "")
    }))
  }))
  default = {}

  validation {
    condition     = alltrue([for name in keys(var.baseline_groups) : startswith(name, var.baseline_prefix) && can(regex("^[A-Za-z0-9._-]{1,128}$", name))])
    error_message = "Baseline group names must start with baseline_prefix and use only letters, digits, '.', '_' and '-'."
  }
  validation {
    condition = alltrue(flatten([for g in values(var.baseline_groups) : [for r in g.fim :
      contains(["directories", "ignore", "nodiff", "windows_registry", "registry_ignore"], r.kind)
    ]]))
    error_message = "fim[].kind must be directories, ignore, nodiff, windows_registry or registry_ignore."
  }
  validation {
    condition = alltrue(flatten([for g in values(var.baseline_groups) : concat(
      [for r in g.fim : !can(regex("[<>&\"\\n]", r.path)) && trimspace(r.reason) != ""],
      [for r in g.fim : alltrue([for k, v in r.attrs : can(regex("^[A-Za-z_][A-Za-z0-9_.-]*$", k)) && !can(regex("[<>&\"\\n]", v))])],
      [for k, v in g.options : can(regex("^[A-Za-z_][A-Za-z0-9_.-]*$", k)) && !can(regex("[<>&\\n]", v))],
    )]))
    error_message = "FIM paths, attributes and options cannot contain < > & \" or line breaks, and every rule needs a reason."
  }
  validation {
    condition     = alltrue([for g in values(var.baseline_groups) : g.os == null ? true : contains(["Linux", "Windows"], g.os)])
    error_message = "os must be Linux, Windows or null (any)."
  }
}

variable "baseline_reconcile" {
  description = "Write the baseline groups at every apply, putting back changes made elsewhere. False: only when the baseline changes."
  type        = bool
  default     = false
}
