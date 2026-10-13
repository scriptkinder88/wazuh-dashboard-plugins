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

### Full agent packages (with CIS-CAT Pro Assessor)

Give the Assessor downloads from the CIS WorkBench as they are (the `.zip`, or a `.tar.gz`, or
an unpacked folder):

```sh
python3 build.py --plugin <plugin zip name> --plugin-sha256 <sha256> --out /srv/ciscat-release \
    --assessor-windows CIS-CAT-Assessor-windows-v4.64.0.zip \
    --assessor-linux   CIS-CAT-Assessor-linux-v4.64.0.zip
```

- The version comes from the file name; otherwise give `--assessor-version X.Y.Z` (both) or
  `--assessor-version-windows` / `--assessor-version-linux`.
- The whole Assessor goes in, every folder and file, as in the download, except the files of
  its `license` and `benchmarks` folders (the folders stay, empty): the master sends the license
  and the benchmarks. `assessor-left-out-<platform>.txt` lists the files left out (names only),
  as the record that no license or benchmark went into the package.
- The build stops if a license or benchmark file is still found anywhere in a package (read back
  from the package itself), if an Assessor is not for its platform (`jre/bin/java.exe` on
  Windows, `jre/bin/java` on Linux), or if an archive holds an absolute or `..` path or a link.
- The file modes in the packages are set by the build, not read from the disk: the launcher,
  the scripts and the JRE of the Linux package are executable (also when the archive, made on
  Windows, carries no exec bits), everything else is 0644. The build gives the same packages
  on Linux and on Windows (MobaXterm, Cygwin).
- Output: `ciscat-agent-windows-<v>-assessor-<a>.zip`, `ciscat-agent-linux-<v>-assessor-<a>.tar.gz`
  and `SHA256SUMS`.

The full packages contain licensed CIS software (CIS-CAT Pro Assessor): keep them in the
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

   A package whose SHA-256 differs is not installed. RHEL hosts registered to Satellite trust
   its CA; Windows hosts need the Satellite CA in their trusted roots (or copy the package from
   the controller: leave `ciscat_package_url` empty and set `ciscat_release_dir`).

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
