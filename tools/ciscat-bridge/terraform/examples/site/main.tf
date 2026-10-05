# VAULT_ADDR and the authentication (VAULT_TOKEN, or the auth method of the site)
# come from the environment, as for the other Terraform code of the site.
provider "vault" {}

data "vault_kv_secret_v2" "wazuh" {
  mount = var.vault_mount
  name  = var.vault_secret
}

locals {
  secret = data.vault_kv_secret_v2.wazuh.data
  # FIM baseline: one file, reviewed like the rest of the code
  baseline = yamldecode(file("${path.module}/baseline.yaml"))
}

module "wazuh_ciscat" {
  source = "../../modules/wazuh-ciscat"

  wazuh_major = var.wazuh_major
  master      = { host = var.master_host, user = var.ssh_user }
  dashboard   = var.dashboard_host == null ? null : { host = var.dashboard_host, user = var.ssh_user }

  installer = { path = var.installer_path, sha256 = var.installer_sha256 }
  plugin    = var.plugin_path == null ? null : { path = var.plugin_path, sha256 = var.plugin_sha256 }

  api_user     = local.secret["api_user"]
  api_password = local.secret["api_password"]

  indexer = var.wazuh_major == 5 ? {
    url    = local.secret["indexer_url"]
    user   = local.secret["indexer_user"]
    ca_pem = lookup(local.secret, "indexer_ca", null)
  } : null
  indexer_password = var.wazuh_major == 5 ? local.secret["indexer_password"] : null

  benchmarks_dir  = var.benchmarks_dir
  baseline_groups = local.baseline.groups
}

output "baseline_groups" {
  value = module.wazuh_ciscat.baseline_groups
}
