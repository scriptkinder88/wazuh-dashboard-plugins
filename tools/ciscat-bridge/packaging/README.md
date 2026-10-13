# CIS-CAT bridge release packages

The sources of the three release packages. The built packages are release attachments, never
committed (`out/` is ignored).

| Folder                                       | Package                                        | Runs on                                                    |
| -------------------------------------------- | ---------------------------------------------- | ---------------------------------------------------------- |
| [`master/`](master/README.txt)               | `ciscat-master-<v>.zip`                        | the Wazuh master (and the dashboard when on the same host) |
| [`agent-windows/`](agent-windows/README.txt) | `ciscat-agent-windows-<v>[-assessor-<a>].zip`  | every Windows agent                                        |
| [`agent-linux/`](agent-linux/README.txt)     | `ciscat-agent-linux-<v>[-assessor-<a>].tar.gz` | every Linux / Unix-like agent                              |
| [`ansible/`](ansible/)                       | playbook and role `ciscat_agent`               | the Ansible controller, to roll out the agent packages     |

## Build

```sh
python3 build.py --plugin <dashboard plugin zip name> --plugin-sha256 <sha256> [--out DIR]
```

The agent installers embed the launcher and bootstrap scripts of this tree, with their SHA-256.

### Final agent packages (with CIS-CAT Pro Assessor)

Given the Assessor downloads from the CIS WorkBench as they are (the `.zip`, or a `.tar.gz`, or an
unpacked folder), the agent packages are **final**: unpacked as they are, with no installer to
run, they are the installation.

```sh
python3 build.py --plugin <plugin zip name> --plugin-sha256 <sha256> --out /srv/ciscat-release \
    --assessor-windows CIS-CAT-Assessor-Windows-jre-v4.67.0.zip \
    --assessor-linux   CIS-CAT-Assessor-Linux-jre-v4.67.0.zip [--master-keys <agent-keys folder>]
```

| Package                                      | Unpacked in | Lays down                                                                                                                                                                                                         |
| -------------------------------------------- | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ciscat-agent-linux-<v>-assessor-<a>.tar.gz` | `/`         | `/opt/ciscat/Assessor` (root only), `/var/ossec/active-response/bin/ciscat-bootstrap.sh` (root:wazuh 0750) and `ciscat-assessor.sha256`, `/var/lib/wazuh-ciscat` (root 0700, with the pinned master key if given) |
| `ciscat-agent-windows-<v>-assessor-<a>.zip`  | `C:\`       | `C:\CIS\Assessor`, and in `C:\Program Files (x86)\ossec-agent\active-response\bin`: `ciscat-assessment.cmd`, `ciscat-bootstrap.ps1`, `ciscat-assessor.sha256` (and the pinned master key if given)                |

Unpacking: `tar -xzpf <package> -C /` as root (GNU tar; elsewhere
`gzip -dc <package> | (cd / && tar -xpf -)`), and on Windows, as Administrator,
`Expand-Archive -Path <package> -DestinationPath C:\ -Force`. The Linux package has entries only
for the bridge's own folders, so unpacking it leaves `/var`, `/var/ossec` and the other folders
as they are. The Linux package serves every Linux and Unix-like agent.

- **The Assessor**: the whole download, every folder and file, except the files of its
  `license` and `benchmarks` folders (the folders stay, empty): the master sends the license and
  the benchmarks (XCCDF, OVAL and CPE files). `assessor-left-out-<platform>.txt` lists the files
  left out (names only), as the record that no license or benchmark went into a package. Its
  settings already have `exit.on.invalid.signature=false`.
- **`ciscat-assessor.sha256`** lists every file of the Assessor but its settings and the
  folders written on the agent. At the first run with a new package the bootstrap checks the
  Assessor against it: a file that differs stops the assessments (alert 100951), files that are
  not in the list (left by an earlier Assessor version) are moved to a `backup-assessor-<date>`
  folder, and the Assessor is made root's only (Linux). On Windows the bootstrap also makes
  `C:\CIS` writable only by SYSTEM and Administrators at every run: a folder unpacked in `C:\`
  inherits the rights of `C:\`, where users may change files.
- **`--master-keys`**: the master's `agent-keys` folder (`ciscat-manifest.pub` and
  `ciscat-manifest.pub.xml`); the packages then pin the master key. Without it each agent keeps
  the first key it receives.
- The version comes from the file name; otherwise give `--assessor-version X.Y.Z` (both) or
  `--assessor-version-windows` / `--assessor-version-linux`. The downloads may hold a second
  archive with the Assessor: it is unpacked too.
- The build stops if a license or benchmark file is still found anywhere in a package (read back
  from the package itself), if an Assessor is not for its platform (`jre/bin/java.exe` on
  Windows, `jre/bin/java` on Linux), or if an archive holds an absolute or `..` path or a link.
- The file modes in the packages are set by the build, not read from the disk: the launcher,
  the scripts and the JRE of the Linux package are executable (also when the archive, made on
  Windows, carries no exec bits), everything else is 0644. The build gives the same packages
  on Linux and on Windows (MobaXterm, Cygwin).
- Output: the two final packages, the master package, `SHA256SUMS`, the end-to-end scripts
  `ciscat-e2e-linux.sh` and `ciscat-e2e-windows.ps1`, and `assessor-left-out-*.txt`.

The final packages contain licensed CIS software (CIS-CAT Pro Assessor): keep them in the
internal release store (Satellite, below), never in a repository. Build them on an internal
host: the Assessor downloads never leave the internal network.

### Distribution through Red Hat Satellite

1. In Satellite, a product (e.g. `CIS-CAT bridge`) with a repository of type **file**, upload
   protection on, no upstream URL.
2. Upload the agent packages and `SHA256SUMS`:
   `hammer repository upload-content --product "CIS-CAT bridge" --name agent-packages --organization <org> --path <file>`.
3. Add the repository to a content view, publish and promote it to the lifecycle environments of
   the agents.
4. Roll out with the Ansible role (Satellite remote execution, or Ansible against the inventory),
   the agents downloading from Satellite:

   ```sh
   ansible-playbook -i inventory.ini ansible/ciscat-agents.yml \
     -e ciscat_package_url=https://<satellite>/pulp/content/<org>/<environment>/<content view>/custom/<product>/<repo> \
     -e ciscat_package_linux=ciscat-agent-linux-<v>-assessor-<a>.tar.gz \
     -e ciscat_package_sha256_linux=<sha256 from SHA256SUMS> \
     -e ciscat_package_windows=ciscat-agent-windows-<v>-assessor-<a>.zip \
     -e ciscat_package_sha256_windows=<sha256 from SHA256SUMS>
   ```

   A package whose SHA-256 differs is not installed. A final package (`-assessor-` in its name) is
   unpacked in `/` or `C:\`; on Windows the role first makes `C:\CIS` writable only by SYSTEM and
   Administrators, so the unpacked files inherit those rights. With `ciscat_master_host` the
   master key is pinned as well. RHEL hosts registered to Satellite trust its CA; Windows hosts
   need the Satellite CA in their trusted roots (or copy the package from the controller: leave
   `ciscat_package_url` empty and set `ciscat_release_dir`). Without Ansible, Satellite remote
   execution can run the unpacking command above on the Linux hosts.

The master package does not carry the Assessor: install it on the master by hand.

Release attachments: the three packages, `SHA256SUMS`, and the dashboard plugin zip of the same
commit.

## Install order

1. Master: `ciscat-master-setup.sh` (see `master/README.txt`). It creates the manifest signing
   key. With `--auto-assign` the agents go into the group of their OS benchmark by themselves
   (every hour).
2. Agents: the agent installer, by hand or with
   `ansible-playbook -i inventory.ini ansible/ciscat-agents.yml -e ciscat_release_dir=<dir>`
   (`<dir>` holds the agent packages). Recommended: set `ciscat_master_host` in the inventory:
   the playbook reads the master's public key on the master and pins it on every agent. Without
   it, each agent keeps the first key it receives with the group files (alert 100953 records it);
   `master/agent-keys/` holds a copy for pinning by hand.
3. End-to-end test: `ciscat-e2e-master.py pre|run|post` on the master, the e2e script of each
   agent package on the agents.

Packages are unpacked in a root/Administrators-only folder: `/opt/ciscat/install/<v>`,
`C:\CIS\install\<v>`. The installers refuse (Linux) or warn about (Windows) a home, temporary or
user-writable folder.

## Updates

| What changes                                                      | How it reaches the agents                                                                                                     | What to do                                      |
| ----------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| Assessment and conversion scripts, benchmarks, OVAL/CPE, settings | from the master at every run, through the signed manifest                                                                     | update the master                               |
| CIS-CAT Pro license                                               | from the master at every run, when `/opt/ciscat/license/license.xml` exists                                                   | replace that file, then `ciscat-fleet.py apply` |
| CIS-CAT Pro Assessor (new version or fix)                         | full agent package (`ASSESSOR_VERSION`): installed when the version differs, license kept, rolled back when it does not start | roll out the new agent package                  |
| Launcher and bootstrap                                            | agent package                                                                                                                 | roll out the agent package                      |

The agent installers are idempotent: running them again with the same package changes nothing
but the files that differ.
