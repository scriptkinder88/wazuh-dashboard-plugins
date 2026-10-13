CIS-CAT bridge 2.3.1 - build kit for the full agent packages (Wazuh 4.14.7)
============================================================================

What it makes (final packages: unpacked as they are, nothing to install or run)
  ciscat-agent-linux-2.3.1-assessor-<a>.tar.gz     every Linux and Unix-like agent, unpacked in /
      /opt/ciscat/Assessor                           CIS-CAT Pro Assessor
      /var/ossec/active-response/bin/ciscat-bootstrap.sh, ciscat-assessor.sha256
      /var/lib/wazuh-ciscat                          bridge data (pinned master key)
  ciscat-agent-windows-2.3.1-assessor-<a>.zip      every Windows agent, unpacked in C:\
      C:\CIS\Assessor                                CIS-CAT Pro Assessor
      C:\Program Files (x86)\ossec-agent\active-response\bin\
          ciscat-assessment.cmd, ciscat-bootstrap.ps1, ciscat-assessor.sha256 (pinned master key)
  ciscat-master-2.3.1.zip                          the Wazuh master (setup and bridge)
  ciscat-e2e-linux.sh, ciscat-e2e-windows.ps1      end-to-end tests for the agents
  SHA256SUMS                                       checksums of the three packages
  assessor-left-out-windows.txt / -linux.txt       what was left out of the CIS downloads

The packages carry the whole Assessor, every folder and file, except the files of its license
and benchmarks folders (benchmarks: XCCDF, OVAL and CPE files). Those folders stay, empty: the
master sends the license and the benchmarks to the agents. On the master, /opt/ciscat/benchmarks
must hold each benchmark with its OVAL and CPE files.

At its first run with a new package the agent's bootstrap checks the Assessor against
ciscat-assessor.sha256 (a file that differs stops the assessments), moves aside the files of an
earlier Assessor and sets the rights of the Assessor folder (and of C:\CIS on Windows).

Unpacking
  Linux / Unix-like, as root:   tar -xzpf ciscat-agent-linux-2.3.1-assessor-<a>.tar.gz -C /
                                (without GNU tar: gzip -dc <file> | (cd / && tar -xpf -))
  Windows, as Administrator:    Expand-Archive -Path ciscat-agent-windows-2.3.1-assessor-<a>.zip -DestinationPath C:\ -Force
  or the Ansible role (packaging/README.md), which unpacks them from Satellite.

Steps, on the Windows PC with MobaXterm (or Cygwin) and python3, or on an internal Linux host
  1. A folder of its own, e.g. C:\CIS-build (MobaXterm: /drives/c/CIS-build), or on Linux
     install -d -m 0700 /srv/ciscat-build. Unpack this kit there.
  2. Put the two Assessor downloads there as downloaded (do not unpack or change them), e.g.
     CIS-CAT-Assessor-Windows-jre-v4.67.0.zip and CIS-CAT-Assessor-Linux-jre-v4.67.0.zip.
     The Assessor version is read from the file name; the order of the two files does not matter.
     To pin the master key, put there also ciscat-manifest.pub and ciscat-manifest.pub.xml
     (from /opt/ciscat/etc on the master).
  3. cd to that folder, then:
       sh ciscat-build-kit-2.3.1/build-full-packages.sh CIS-CAT-Assessor-Windows-jre-v4.67.0.zip \
         CIS-CAT-Assessor-Linux-jre-v4.67.0.zip
     Expected: "RESULT: OK". It stops when a download is for the other platform, holds an
     unsafe path, or a license or benchmark file would end up in a package. The file modes of
     the Linux package (executable launcher, scripts and JRE) are set by the build, so building
     on Windows gives the same package as on Linux.
  4. Keep SHA256SUMS and the assessor-left-out-*.txt files with the release record. The
     packages are in ciscat-build-kit-2.3.1/release-2.3.1.

Production bundle (everything for a Wazuh master in one file)
  sh ciscat-build-kit-2.3.1/build-prod-bundle.sh CIS-CAT-Assessor-Windows-jre-v4.67.0.zip \
     CIS-CAT-Assessor-Linux-jre-v4.67.0.zip
  Next to the downloads, when there: the dashboard plugin zip of this release, license.xml,
  ciscat-config-<date>.tgz (+ .sha256) exported from another master. Not the master's key files:
  the agents take the key from their master.
  -> release-2.3.1/ciscat-prod-2.3.1.tar.gz: master package, plugin, all CIS benchmarks of the two
     downloads (XCCDF, OVAL, CPE), license, configuration, final agent packages (agents/), and
     install-prod.sh. On the master, as root:
       install -d -m 0700 /opt/ciscat/install/bundle
       tar -xzf ciscat-prod-2.3.1.tar.gz -C /opt/ciscat/install/bundle
       cd /opt/ciscat/install/bundle/ciscat-prod-2.3.1 && sh install-prod.sh
     It verifies the bundle, installs everything and publishes the groups; the only question is,
     the first time, a Wazuh API administrator to create the bridge's API user (never stored).
     Expected: "RESULT: OK". The agents/ folder holds the packages to load into Satellite.

Test before Satellite (ITTEST, one Windows and one Linux agent)
  - Install the agent package as in its README.txt: the installer prints
    "installing Assessor <a> (was: <old>)", "license: ..." and RESULT: OK.
  - Run the installer again: "Assessor <a> already installed".
  - End-to-end test of the package (pre, run from the master, post): all PASS, and the agent log
    shows "CIS-CAT version: <a>".

Satellite
  - File repository (no upstream URL), upload the three packages and SHA256SUMS, add it to the
    content view, publish and promote.
  - Roll out with the Ansible role, the agents downloading from Satellite with the SHA-256
    checked: see ciscat-bridge/packaging/README.md, "Distribution through Red Hat Satellite".

The dashboard plugin is not in this kit: it is the release attachment
wazuh-dashboard-plugins_wazuh_4.14.7-01_f7ccb4e866af66c6ee2377d672bc6619336a1b02.zip (unchanged).
