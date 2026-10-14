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
   When the Wazuh dashboard runs on another host, copy the same archive there and run
     sh align-prod.sh --dashboard-only
   Recommended before (Wazuh upgrade guide): export the saved objects (Dashboard management >
   Dashboards Management > Saved objects > Export all objects); the script does not touch them.

   PCI DSS reporting of this site, part by part (Wazuh 4.14 documentation and plugin code):
     rule.pci_dss of the alerts: rules in /var/ossec/etc/rules (overwrite="yes" rules too),
       /var/ossec/ruleset, <ruleset> of ossec.conf          not touched, checked at the end
     report header, footer, customization.* settings:
       /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml   not touched, checked at the end
     report logo and other custom images: inside the Wazuh plugin folder,
       plugins/wazuh/public/assets/custom/images (a plugin reinstall wipes them)   put back
     requirement texts (e.g. updated to PCI DSS 4.0.1), inside the Wazuh plugin folder:
       server/integration-files/pci-requirements-pdfmake.js (PDF report),
       common/compliance-requirements/pci-requirements.js                          put back
     dashboards and visualizations (saved objects, in the indexer)                not touched
   It stops before changing anything when the Wazuh plugin has other local changes (e.g. the
   module pages edited in the plugin bundles: those cannot be carried over), or a custom plugin
   of the bundle would replace a different one; then
     sh align-prod.sh --no-dashboard-plugins
   aligns everything else and leaves every dashboard plugin as it is.

   It saves what it replaces in /opt/ciscat/backup/prod-before-<date> (pci-keep/: this site's
   PCI DSS files of the plugin), puts the files in place (benchmarks and tailoring files the
   other master does not have are moved to the backup), runs the master setup, publishes the
   groups, puts this site's PCI DSS files back and restarts the dashboard. The only question:
   the first time, a Wazuh API administrator, to create the bridge's own API user (never
   stored). At the end it compares every protected file with its checksum from before:
   "RESULT: OK", or "RESULT: CHECK" with the file that changed.

The agent packages stay the ones already built: they carry no key, the agents take the key
of their master.
