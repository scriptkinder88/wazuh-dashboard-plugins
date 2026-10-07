output "bridge_installer_sha256" {
  description = "SHA-256 of the bridge installer last run on the master."
  value       = var.installer.sha256
}

output "baseline_groups" {
  description = "Groups owned by Terraform."
  value       = sort(keys(var.baseline_groups))
}

output "baseline_agent_conf" {
  description = "agent.conf written to each baseline group (to review in a plan)."
  value       = jsondecode(local.baseline).groups
}
