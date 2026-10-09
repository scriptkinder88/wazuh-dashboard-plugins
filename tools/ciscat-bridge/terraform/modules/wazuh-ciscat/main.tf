/*
 * CIS-CAT bridge, dashboard plugin and baseline groups on existing Wazuh hosts.
 *
 * Everything runs over SSH with terraform_data: files are uploaded to a private
 * folder of the SSH user, checked (SHA-256) and moved in place as root; the
 * installer is idempotent and keeps a backup of what it changes; the baseline
 * groups are written through the Wazuh API by ciscat-fleet.py baseline.
 * Day-to-day changes (FIM rules, exclusions, schedules) stay in the dashboard:
 * only the groups starting with var.baseline_prefix belong to Terraform.
 */

locals {
  # upload folder in the SSH user's home (scp resolves relative paths there)
  up     = ".ciscat-terraform"
  remote = "$HOME/${local.up}"
  etc    = "/opt/ciscat/etc"

  sudo_master    = var.master.user == "root" ? "" : "sudo -n "
  sudo_dashboard = var.dashboard == null ? "" : (var.dashboard.user == "root" ? "" : "sudo -n ")

  plugin_on_master = var.plugin != null && var.dashboard == null
  plugin_file      = var.plugin == null ? "" : "${local.remote}/${basename(var.plugin.path)}"
  plugin_args      = var.plugin == null ? "" : "--plugin-file \"${local.plugin_file}\" --plugin-sha256 ${var.plugin.sha256} --restart-dashboard"

  master_args = join(" ", compact([
    var.apply_policies ? "--apply" : "",
    local.plugin_on_master ? local.plugin_args : "",
  ]))

  prepare = ["set -e", "umask 077", "mkdir -p ${local.remote}", "chmod 700 ${local.remote}"]

  baseline_rules = {
    for name, g in var.baseline_groups : name => [for r in g.fim : {
      kind  = r.kind
      path  = trimspace(r.path)
      attrs = r.attrs
      # same audit comment as the dashboard (standard base64 of the JSON)
      meta = base64encode(jsonencode({
        at = r.since, by = "terraform", owner = r.owner, reason = r.reason, ticket = r.ticket
      }))
    }]
  }
  baseline = jsonencode({
    groups = {
      for name, g in var.baseline_groups : name => {
        agents = g.agents
        agent_conf = templatefile("${path.module}/templates/agent.conf.tftpl", {
          group   = name
          os      = g.os
          options = g.options
          rules   = local.baseline_rules[name]
        })
      }
    }
  })

  benchmark_files = var.benchmarks_dir == null ? [] : sort(fileset(var.benchmarks_dir, "*.xml"))
}

# --- secrets: root-only files, never on a command line ----------------------------------------
resource "terraform_data" "secrets" {
  # the hashes only tell Terraform when to rewrite the files
  triggers_replace = {
    api  = sha256("${var.api_user}\n${var.api_password}")
    host = var.master.host
  }

  connection {
    type         = "ssh"
    host         = var.master.host
    user         = var.master.user
    port         = var.master.port
    private_key  = var.ssh_private_key
    agent        = var.ssh_private_key == null
    bastion_host = var.master.bastion_host
    bastion_user = var.master.bastion_user
  }

  provisioner "remote-exec" {
    inline = local.prepare
  }

  provisioner "file" {
    content     = var.api_password
    destination = "${local.up}/api.pass"
  }

  provisioner "remote-exec" {
    inline = [
      "set -e",
      "S='${local.sudo_master}'",
      "$S install -d -m 700 -o root -g root ${local.etc}",
      "$S install -m 600 -o root -g root ${local.remote}/api.pass ${local.etc}/.ciscat_api_pass",
      "rm -f ${local.remote}/api.pass",
      # api_user and api_pass_file in the bridge configuration, other settings kept
      "$S python3 - '${local.etc}/ciscat-orchestrator.conf' '${var.api_user}' '${local.etc}/.ciscat_api_pass' <<'PY'",
      "import os, sys",
      "path, user, pfile = sys.argv[1:]",
      "lines = open(path).read().splitlines() if os.path.exists(path) else []",
      "keep = [l for l in lines if l.split('=', 1)[0].strip() not in ('api_user', 'api_pass_file')]",
      "open(path, 'w').write('\\n'.join(keep + ['api_user=' + user, 'api_pass_file=' + pfile]) + '\\n')",
      "os.chmod(path, 0o640)",
      "PY",
    ]
  }
}

# --- licensed content: benchmarks and first exclusions -----------------------------------------
resource "terraform_data" "benchmarks" {
  count = var.benchmarks_dir == null ? 0 : 1

  triggers_replace = {
    files = sha256(join("\n", [for f in local.benchmark_files : "${f} ${filemd5("${var.benchmarks_dir}/${f}")}"]))
  }

  connection {
    type         = "ssh"
    host         = var.master.host
    user         = var.master.user
    port         = var.master.port
    private_key  = var.ssh_private_key
    agent        = var.ssh_private_key == null
    bastion_host = var.master.bastion_host
    bastion_user = var.master.bastion_user
  }

  provisioner "remote-exec" {
    inline = concat(local.prepare, ["rm -rf ${local.remote}/benchmarks", "mkdir ${local.remote}/benchmarks"])
  }

  provisioner "file" {
    source      = "${var.benchmarks_dir}/"
    destination = "${local.up}/benchmarks"
  }

  provisioner "remote-exec" {
    inline = [
      "set -e",
      "S='${local.sudo_master}'",
      "$S install -d -m 755 /opt/ciscat/benchmarks",
      "$S install -m 644 -o root -g root ${local.remote}/benchmarks/*.xml /opt/ciscat/benchmarks/",
      "rm -rf ${local.remote}/benchmarks",
    ]
  }

  depends_on = [terraform_data.secrets]
}

resource "terraform_data" "exclusions_seed" {
  for_each = var.exclusions_seed

  # read only by the first install: afterwards exclusions are managed in the dashboard
  triggers_replace = { file = each.key, content = sha256(each.value) }

  connection {
    type         = "ssh"
    host         = var.master.host
    user         = var.master.user
    port         = var.master.port
    private_key  = var.ssh_private_key
    agent        = var.ssh_private_key == null
    bastion_host = var.master.bastion_host
    bastion_user = var.master.bastion_user
  }

  provisioner "remote-exec" {
    inline = local.prepare
  }

  provisioner "file" {
    content     = each.value
    destination = "${local.up}/${each.key}.csv"
  }

  provisioner "remote-exec" {
    inline = [
      "set -e",
      "S='${local.sudo_master}'",
      "$S install -d -m 750 /opt/ciscat/tailoring/exclusions",
      "$S install -m 640 ${local.remote}/${each.key}.csv /opt/ciscat/tailoring/exclusions/${each.key}.csv",
      "rm -f ${local.remote}/${each.key}.csv",
    ]
  }

  depends_on = [terraform_data.secrets]
}

# --- bridge (and plugin, when the dashboard runs on the master) ---------------------------------
resource "terraform_data" "master_plugin_upload" {
  count = local.plugin_on_master ? 1 : 0

  triggers_replace = { plugin = var.plugin.sha256 }

  connection {
    type         = "ssh"
    host         = var.master.host
    user         = var.master.user
    port         = var.master.port
    private_key  = var.ssh_private_key
    agent        = var.ssh_private_key == null
    bastion_host = var.master.bastion_host
    bastion_user = var.master.bastion_user
  }

  provisioner "remote-exec" {
    inline = local.prepare
  }

  provisioner "file" {
    source      = var.plugin.path
    destination = "${local.up}/${basename(var.plugin.path)}"
  }
}

resource "terraform_data" "master" {
  triggers_replace = {
    installer = var.installer.sha256
    plugin    = local.plugin_on_master ? var.plugin.sha256 : ""
    args      = local.master_args
    secrets   = terraform_data.secrets.id
  }

  connection {
    type         = "ssh"
    host         = var.master.host
    user         = var.master.user
    port         = var.master.port
    private_key  = var.ssh_private_key
    agent        = var.ssh_private_key == null
    bastion_host = var.master.bastion_host
    bastion_user = var.master.bastion_user
  }

  provisioner "remote-exec" {
    inline = local.prepare
  }

  provisioner "file" {
    source      = var.installer.path
    destination = "${local.up}/ciscat-bridge-install.sh"
  }

  provisioner "remote-exec" {
    inline = compact([
      "set -e",
      "cd ${local.remote}",
      "echo '${var.installer.sha256}  ciscat-bridge-install.sh' | sha256sum -c -",
      local.plugin_on_master ? "echo '${var.plugin.sha256}  ${basename(var.plugin.path)}' | sha256sum -c -" : "",
      "${local.sudo_master}sh ${local.remote}/ciscat-bridge-install.sh ${local.master_args}",
      local.plugin_on_master ? "rm -f \"${local.plugin_file}\"" : "",
    ])
  }

  depends_on = [
    terraform_data.benchmarks,
    terraform_data.exclusions_seed,
    terraform_data.master_plugin_upload,
  ]
}

# --- plugin on a separate dashboard host ---------------------------------------------------------
resource "terraform_data" "dashboard" {
  count = var.plugin != null && var.dashboard != null ? 1 : 0

  triggers_replace = {
    installer = var.installer.sha256
    plugin    = var.plugin.sha256
  }

  connection {
    type         = "ssh"
    host         = var.dashboard.host
    user         = var.dashboard.user
    port         = var.dashboard.port
    private_key  = var.ssh_private_key
    agent        = var.ssh_private_key == null
    bastion_host = var.dashboard.bastion_host
    bastion_user = var.dashboard.bastion_user
  }

  provisioner "remote-exec" {
    inline = local.prepare
  }

  provisioner "file" {
    source      = var.installer.path
    destination = "${local.up}/ciscat-bridge-install.sh"
  }

  provisioner "file" {
    source      = var.plugin.path
    destination = "${local.up}/${basename(var.plugin.path)}"
  }

  provisioner "remote-exec" {
    inline = [
      "set -e",
      "cd ${local.remote}",
      "echo '${var.installer.sha256}  ciscat-bridge-install.sh' | sha256sum -c -",
      "echo '${var.plugin.sha256}  ${basename(var.plugin.path)}' | sha256sum -c -",
      "${local.sudo_dashboard}sh ${local.remote}/ciscat-bridge-install.sh ${local.plugin_args}",
      "rm -f \"${local.plugin_file}\"",
    ]
  }
}

# --- baseline groups --------------------------------------------------------------------------
resource "terraform_data" "baseline" {
  count = length(var.baseline_groups) > 0 ? 1 : 0

  triggers_replace = {
    baseline  = sha256(local.baseline)
    reconcile = var.baseline_reconcile ? timestamp() : ""
    bridge    = terraform_data.master.id
  }

  connection {
    type         = "ssh"
    host         = var.master.host
    user         = var.master.user
    port         = var.master.port
    private_key  = var.ssh_private_key
    agent        = var.ssh_private_key == null
    bastion_host = var.master.bastion_host
    bastion_user = var.master.bastion_user
  }

  provisioner "remote-exec" {
    inline = local.prepare
  }

  provisioner "file" {
    content     = local.baseline
    destination = "${local.up}/baseline.json"
  }

  provisioner "remote-exec" {
    inline = [
      "set -e",
      "${local.sudo_master}python3 /opt/ciscat/bin/ciscat-fleet.py baseline --file ${local.remote}/baseline.json",
      "rm -f ${local.remote}/baseline.json",
    ]
  }
}
