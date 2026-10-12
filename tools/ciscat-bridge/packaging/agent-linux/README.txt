agent-linux - CIS-CAT bridge @VERSION@
=======================================
For every Linux / Unix-like agent (RHEL, Oracle Linux, Rocky, Debian...). Shell only: no
PowerShell, no Python. openssl is needed (manifest signatures).

Where to unpack (root): never in /root, /home or /tmp. A dedicated root-only folder:
    install -d -m 0700 -o root -g root /opt/ciscat/install/@VERSION@
    cd /opt/ciscat/install/@VERSION@ && tar -xzf <package tar.gz> && chmod -R go-w .
The installer stops when the folder is in a home or temporary folder, or writable by others.

1. Copy ciscat-manifest.pub (from master/agent-keys after ciscat-master-setup.sh) into the
   agent-linux/ folder, or pass --pubkey <file>. Compare the sha256 the installer prints with
   the one the master setup printed.

2. Install or update, root, in the agent-linux/ folder:
     sh install-linux-agent.sh
   - CIS-CAT Pro in /opt/ciscat/Assessor: installed or updated from the package when it carries
     the Assessor (ASSESSOR_VERSION), keeping the license; a new version whose Java does not
     start is rolled back; /opt/ciscat and the Assessor owned by root;
   - exit.on.invalid.signature=false (the tailored benchmark is unsigned);
   - ciscat-bootstrap.sh (root:wazuh 0750) in active-response/bin and the master's public key
     in /var/lib/wazuh-ciscat;
   - files of earlier versions moved to /var/lib/wazuh-ciscat/backup-<date>;
   - SELinux: default labels (restorecon) on /opt/ciscat and /var/lib/wazuh-ciscat.
   Everything else comes from the master at each run, through the signed manifest.
   Expected: "RESULT: OK". Exit code 0 = done.

3. Test, after the master setup and with the agent in the group of its OS:
     sh ciscat-e2e-linux.sh pre
   then, after "run" on the master: sh ciscat-e2e-linux.sh watch, and when it ends: post
