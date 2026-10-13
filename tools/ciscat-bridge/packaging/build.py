#!/usr/bin/env python3
"""Builds the release packages of the CIS-CAT bridge from this repository (see README.md):

  ciscat-master-<v>.zip          master: setup, bridge installer, API user, export, e2e test
  ciscat-agent-windows-<v>.zip   Windows agent: installer (launcher + bootstrap embedded), e2e test
  ciscat-agent-linux-<v>.tar.gz  Linux agent: installer (bootstrap embedded), e2e test

With --assessor-windows / --assessor-linux (a CIS-CAT Pro Assessor folder, without its license)
the agent packages also carry the Assessor, installed or updated by the agent installer. They
contain licensed CIS software: keep them in the internal release store, never in a repository.

  python3 build.py --plugin <plugin zip name> --plugin-sha256 <sha256> [--out DIR]
                   [--assessor-windows DIR --assessor-linux DIR --assessor-version X.Y.Z]
"""
import argparse
import base64
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
BRIDGE = os.path.dirname(HERE)
AGENT = os.path.join(BRIDGE, "agent", "active-response")
WAZUH = "4.14.8"
# files of an Assessor folder that never go into a package
SKIP_DIRS = {"license", "reports", "logs"}


def version():
    with open(os.path.join(BRIDGE, "bin", "ciscat-fleet.py"), encoding="utf-8") as f:
        return re.search(r'^VERSION = "([^"]+)"', f.read(), re.M).group(1)


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def b64(path, lines=False):
    with open(path, "rb") as f:
        data = f.read()
    return (base64.encodebytes(data).decode().strip() if lines else base64.b64encode(data).decode())


def render(src, subs, crlf=False):
    with open(src, encoding="utf-8") as f:
        text = f.read()
    for k, v in subs.items():
        text = text.replace("@{0}@".format(k), v)
    left = re.findall(r"@[A-Z_]{3,}@", text)
    if left:
        sys.exit("unfilled placeholder(s) {0} in {1}".format(sorted(set(left)), src))
    if crlf:
        text = text.replace("\r\n", "\n").replace("\n", "\r\n")
    return text


def write(path, text, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    os.chmod(path, mode)


def sums(folder):
    lines = []
    for root, dirs, files in os.walk(folder):
        dirs.sort()
        for name in sorted(files):
            if name == "SHA256SUMS":
                continue
            p = os.path.join(root, name)
            lines.append("{0}  {1}".format(sha(p), os.path.relpath(p, folder)))
    write(os.path.join(folder, "SHA256SUMS"), "\n".join(lines) + "\n")


def copy_assessor(src, dest):
    """The Assessor folder without license, reports and logs."""
    if not os.path.isdir(src):
        sys.exit("Assessor folder not found: " + src)

    def ignore(folder, names):
        return [n for n in names if os.path.abspath(folder) == os.path.abspath(src)
                and n.lower() in SKIP_DIRS]
    shutil.copytree(src, dest, ignore=ignore, symlinks=False)


def zip_folder(folder, out):
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(folder):
            dirs.sort()
            for name in sorted(files):
                p = os.path.join(root, name)
                info = zipfile.ZipInfo(os.path.relpath(p, os.path.dirname(folder)),
                                       (2026, 1, 1, 0, 0, 0))
                info.external_attr = (os.stat(p).st_mode & 0o777) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                with open(p, "rb") as f:
                    zf.writestr(info, f.read())


def tar_folder(folder, out):
    def norm(ti):
        ti.uid = ti.gid = 0
        ti.uname = ti.gname = "root"
        ti.mtime = 1767225600
        return ti
    with tarfile.open(out, "w:gz") as tf:
        tf.add(folder, arcname=os.path.basename(folder), filter=norm)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--plugin", required=True, help="file name of the dashboard plugin zip")
    ap.add_argument("--plugin-sha256", required=True, help="sha256 of the plugin zip")
    ap.add_argument("--out", default=os.path.join(HERE, "out"))
    ap.add_argument("--assessor-windows", help="CIS-CAT Pro Assessor folder for Windows")
    ap.add_argument("--assessor-linux", help="CIS-CAT Pro Assessor folder for Linux")
    ap.add_argument("--assessor-version", help="version of those Assessor folders, e.g. 4.62.0")
    a = ap.parse_args()
    if not re.match(r"^[0-9a-f]{64}$", a.plugin_sha256):
        sys.exit("--plugin-sha256: 64 hex characters expected")
    if (a.assessor_windows or a.assessor_linux) and not re.match(r"^\d+(\.\d+)+$",
                                                                 a.assessor_version or ""):
        sys.exit("--assessor-version X.Y.Z is needed with an Assessor folder")
    v = version()
    subs = {"VERSION": v, "WAZUH": WAZUH}
    out = os.path.abspath(a.out)
    shutil.rmtree(out, ignore_errors=True)
    work = os.path.join(out, "work")

    # bridge installer (embeds bin/, agent/, rules/)
    subprocess.run([sys.executable, os.path.join(BRIDGE, "installer", "build.py")], check=True,
                   stdout=subprocess.DEVNULL)
    installer = os.path.join(BRIDGE, "dist", "ciscat-bridge-install-{0}.sh".format(v))

    # master
    m = os.path.join(work, "master")
    os.makedirs(m)
    shutil.copy(installer, m)
    src = os.path.join(HERE, "master")
    msubs = dict(subs, INSTALLER=os.path.basename(installer), PLUGIN=a.plugin,
                 PLUGIN_SHA=a.plugin_sha256)
    for name, mode in (("ciscat-master-setup.sh", 0o755), ("ciscat-export-config.sh", 0o755),
                       ("ciscat-api-user.py", 0o750), ("ciscat-e2e-master.py", 0o755),
                       ("README.txt", 0o644)):
        write(os.path.join(m, name), render(os.path.join(src, name), msubs), mode)
    sums(m)

    # Windows agent
    w = os.path.join(work, "agent-windows")
    src = os.path.join(HERE, "agent-windows")
    files = "\n".join("    '{0}' = @('{1}', '{2}')".format(
        n, sha(os.path.join(AGENT, n)).upper(), b64(os.path.join(AGENT, n)))
        for n in ("ciscat-assessment.cmd", "ciscat-bootstrap.ps1"))
    wsubs = dict(subs, FILES=files,
                 CMD_SHA=sha(os.path.join(AGENT, "ciscat-assessment.cmd")).upper(),
                 BOOT_SHA=sha(os.path.join(AGENT, "ciscat-bootstrap.ps1")).upper())
    for name in ("install-windows-agent.ps1", "ciscat-e2e-windows.ps1", "README.txt"):
        write(os.path.join(w, name), render(os.path.join(src, name), wsubs, crlf=True))
    if a.assessor_windows:
        copy_assessor(a.assessor_windows, os.path.join(w, "Assessor"))
        write(os.path.join(w, "ASSESSOR_VERSION"), a.assessor_version + "\r\n")
    sums(w)

    # Linux agent
    li = os.path.join(work, "agent-linux")
    src = os.path.join(HERE, "agent-linux")
    boot = os.path.join(BRIDGE, "bin", "ciscat-bootstrap.sh")
    lsubs = dict(subs, BOOTSTRAP_SHA=sha(boot), BOOTSTRAP_B64=b64(boot, lines=True))
    for name, mode in (("install-linux-agent.sh", 0o755), ("ciscat-e2e-linux.sh", 0o755),
                       ("README.txt", 0o644)):
        write(os.path.join(li, name), render(os.path.join(src, name), lsubs), mode)
    if a.assessor_linux:
        copy_assessor(a.assessor_linux, os.path.join(li, "Assessor"))
        write(os.path.join(li, "ASSESSOR_VERSION"), a.assessor_version + "\n")
    sums(li)

    suffix = "-assessor-" + a.assessor_version if a.assessor_version else ""
    results = [
        (m, os.path.join(out, "ciscat-master-{0}.zip".format(v)), zip_folder),
        (w, os.path.join(out, "ciscat-agent-windows-{0}{1}.zip".format(
            v, suffix if a.assessor_windows else "")), zip_folder),
        (li, os.path.join(out, "ciscat-agent-linux-{0}{1}.tar.gz".format(
            v, suffix if a.assessor_linux else "")), tar_folder),
    ]
    lines = []
    for folder, path, pack in results:
        pack(folder, path)
        lines.append("{0}  {1}".format(sha(path), os.path.basename(path)))
    shutil.rmtree(work)
    write(os.path.join(out, "SHA256SUMS"), "\n".join(lines) + "\n")
    print("\n".join(lines))
    if a.assessor_windows or a.assessor_linux:
        print("contains CIS-CAT Pro (licensed): internal release store only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
