master - CIS-CAT bridge @VERSION@ (Wazuh @WAZUH@)
==================================================
Where to unpack (root): never in /root, /home or /tmp. A dedicated root-only folder:
    install -d -m 0700 -o root -g root /opt/ciscat/install/@VERSION@
    cd /opt/ciscat/install/@VERSION@ && unzip -o ciscat-master-@VERSION@.zip && chmod -R go-w .
The setup stops when the folder is in a home or temporary folder, or writable by other users.
The folder stays for rollback and audit (hashes in SHA256SUMS).

A) Moving from another master (optional), on that master, root:
     sh ciscat-export-config.sh
   -> ciscat-config-<date>.tgz and .tgz.sha256: the CIS benchmarks (licensed: keep them
   internal), os-library.json, exclusions, schedules, benchmark groups, tailoring. No password,
   token, API setting or signing key.

B) Dashboard plugin: put the release attachment @PLUGIN@ in the master/ folder.
   Expected sha256 (checked by the setup before installing it):
     @PLUGIN_SHA@

C) On the master, root, in the master/ folder:
     sh ciscat-master-setup.sh [--import ciscat-config-<date>.tgz [--with-targets]]
                               [--no-dashboard] [--new-api-user]
   The setup checks Wazuh @WAZUH@ and the package files, creates /opt/ciscat (root), imports the
   benchmarks, creates the API user "ciscat-bridge" (role and policies with only the rights the
   bridge uses, random password in a root-only file; an API administrator is asked once and
   never stored; --new-api-user rotates it and refreshes the role), adds the Active Response
   commands to ossec.conf (backup, checked by wazuh-analysisd -t), installs the bridge, restarts
   the manager and installs the plugin when the dashboard runs on this host.
   It creates once the key the master signs the manifests with and copies its public part to
   agent-keys/: ciscat-manifest.pub for the Linux agents, ciscat-manifest.pub.xml for the
   Windows agents, with the sha256 to compare. The private key stays in /opt/ciscat/etc, root
   only, and is never exported.
   Expected at the end: "RESULT: OK".

D) CIS-CAT Pro license (optional): copy license.xml to /opt/ciscat/license/license.xml (root,
   0600) and run "ciscat-fleet.py apply": every agent gets it through the signed manifest at
   its next run. Renewal: replace the file and apply again.

E) After the agents, the end-to-end test (agent id or name):
     python3 ciscat-e2e-master.py pre  <agent> [<agent> ...]
     python3 ciscat-e2e-master.py run  <agent> [<agent> ...]
     python3 ciscat-e2e-master.py post <agent> [<agent> ...]
