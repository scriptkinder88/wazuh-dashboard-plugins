CIS-CAT bridge 2.3.1 - one-time alignment of a Wazuh master to the configured (test) master
============================================================================================

Two steps, two files.

1. On the configured master (the test master), as root:
     install -d -m 0700 /opt/ciscat/install/capture
     cd /opt/ciscat/install/capture && unzip ciscat-capture-kit-2.3.1.zip
     cd ciscat-capture-kit-2.3.1 && sh capture-ittest.sh
   It reads the master and writes out/ciscat-prod-2.3.1-<date>.tar.gz (+ .sha256) with:
     root/opt/ciscat/benchmarks/        original CIS benchmarks (XCCDF, OVAL, CPE)
     root/opt/ciscat/license/           CIS-CAT Pro license
     root/opt/ciscat/etc/os-library.json
     root/opt/ciscat/tailoring/exclusions/
     root/var/ossec/etc/lists/          ciscat-exclusions, ciscat-schedule, ciscat-targets
     wazuh-dashboard-plugins_wazuh_*.zip   the dashboard plugin of this release
     dashboard-plugins/                 other plugins changed from the wazuh-dashboard package
     ciscat-master-2.3.1.zip, align-prod.sh, ittest-info.txt, SHA256SUMS
   The plugin zip is looked for next to capture-ittest.sh and under /opt/ciscat/install.
   Never in the archive: API passwords and settings, signing keys, agent status and history.
   The archive holds licensed CIS content: keep it inside the organization.

2. On the master to align (production), as root:
     install -d -m 0700 /opt/ciscat/install/bundle
     tar -xzf ciscat-prod-2.3.1-<date>.tar.gz -C /opt/ciscat/install/bundle
     cd /opt/ciscat/install/bundle/ciscat-prod-2.3.1 && sh align-prod.sh
   First it checks, changing nothing. It stops when the Wazuh plugin of the dashboard has
   local changes (a customized PCI DSS report, for instance) that the plugin of the bundle
   would replace; then
     sh align-prod.sh --no-dashboard-plugins
   aligns everything else and leaves every dashboard plugin as it is.
   It saves what it replaces in /opt/ciscat/backup/prod-before-<date>, puts the files in place
   (benchmarks and tailoring files the other master does not have are moved to the backup),
   runs the master setup and publishes the groups. The only question: the first time, a Wazuh
   API administrator, to create the bridge's own API user (never stored).
   At the end it checks that the dashboard settings (wazuh.yml: report header, footer, logos),
   /etc/wazuh-dashboard, the Wazuh rules and decoders and the agent groups not managed by the
   bridge are as before: "RESULT: OK". "RESULT: CHECK" lists a file that changed.

The agent packages stay the ones already built: they carry no key, the agents take the key
of their master.
