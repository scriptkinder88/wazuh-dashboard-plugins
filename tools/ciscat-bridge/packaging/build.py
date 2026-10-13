#!/usr/bin/env python3
"""Builds the release packages of the CIS-CAT bridge from this repository (see README.md):

  ciscat-master-<v>.zip          master: setup, bridge installer, API user, export, e2e test
  ciscat-agent-windows-<v>.zip   Windows agent: installer (launcher + bootstrap embedded), e2e test
  ciscat-agent-linux-<v>.tar.gz  Linux agent: installer (bootstrap embedded), e2e test

With --assessor-windows / --assessor-linux (the CIS-CAT Pro Assessor as downloaded from CIS,
a .zip or .tar.gz, or its unpacked folder) the agent packages are final instead: unpacked as
they are, with no installer to run, they lay down the Assessor and the bridge's agent files.

  ciscat-agent-linux-<v>-assessor-<a>.tar.gz    unpacked in /  (Linux and other Unix-like)
      opt/ciscat/Assessor/                           the Assessor
      var/ossec/active-response/bin/ciscat-bootstrap.sh, ciscat-assessor.sha256
      var/lib/wazuh-ciscat/                          bridge data (and the pinned master key)
  ciscat-agent-windows-<v>-assessor-<a>.zip     unpacked in C:\
      CIS/Assessor/                                  the Assessor
      Program Files (x86)/ossec-agent/active-response/bin/
                                    ciscat-assessment.cmd, ciscat-bootstrap.ps1,
                                    ciscat-assessor.sha256 (and the pinned master key)

ciscat-assessor.sha256 lists every file of the Assessor: at its first run with a new package
the bootstrap checks them (and stops if one differs), moves aside the files of an earlier
Assessor and sets the owner and rights of the Assessor folder. The whole Assessor goes in,
every folder and file, except the
files of its license and benchmarks folders (the master sends both); the build stops if a
license or benchmark file is still found anywhere in a package. The version is read from the
archive name (e.g.
CIS-CAT-Assessor-linux-v4.64.0.zip) unless given. The packages contain licensed CIS software:
keep them in the internal release store, never in a repository.

  python3 build.py --plugin <plugin zip name> --plugin-sha256 <sha256> [--out DIR]
                   [--assessor-windows ZIP|DIR] [--assessor-linux ZIP|TAR.GZ|DIR]
                   [--assessor-version X.Y.Z | --assessor-version-windows X.Y.Z
                    --assessor-version-linux X.Y.Z] [--master-keys DIR]
"""
import argparse
import base64
import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
BRIDGE = os.path.dirname(HERE)
AGENT = os.path.join(BRIDGE, "agent", "active-response")
WAZUH = "4.14.8"
# folders of the Assessor whose files never go into a package (the folders stay, empty): the
# master sends the license and the benchmarks
MASTER_DIRS = {"license", "benchmarks"}
# license and benchmark files, which must not be anywhere in a package
# (benchmarks: the XCCDF files and their OVAL and CPE files)
LICENSED_RE = re.compile(
    r"^(license|benchmarks)/.|(^|/)license\.xml$|\.lic$|(^|/)CIS_[^/]*\.(xml|zip)$|"
    r"-(xccdf|oval|cpe-dictionary|cpe-oval)\.xml$|(^|/|[-_.])oval([-_.][^/]*)?\.xml$", re.I)
# File modes in the packages come from the build, not from the disk: on Windows (Cygwin,
# MobaXterm, Git Bash) the disk does not keep them. Paths not listed get 0644 there.
MODES = {}
TRUST_DISK_MODES = sys.platform not in ("cygwin", "msys", "win32")
VERSION_RE = re.compile(r"(?<![0-9.])v?(\d+\.\d+\.\d+)(?![0-9])")


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


def set_mode(path, mode):
    MODES[os.path.abspath(path)] = mode
    os.chmod(path, mode)


def mode_of(path):
    path = os.path.abspath(path)
    if path in MODES:
        return MODES[path]
    return os.stat(path).st_mode & 0o777 if TRUST_DISK_MODES else 0o644


def write(path, text, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    set_mode(path, mode)


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


def unpack(archive, dest):
    """A .zip or .tar.gz into dest: no absolute path, no "..", no link or device file."""
    def safe(name):
        parts = name.replace("\\", "/").split("/")
        if name.startswith(("/", "\\")) or ".." in parts or re.match(r"^[A-Za-z]:", name):
            sys.exit("unsafe path in {0}: {1}".format(archive, name))
        return os.path.join(dest, *[x for x in parts if x not in ("", ".")])
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    sys.exit("link in {0}: {1}".format(archive, info.filename))
                path = safe(info.filename)
                if info.is_dir():
                    os.makedirs(path, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with zf.open(info) as src, open(path, "wb") as f:
                    shutil.copyfileobj(src, f)
                set_mode(path, 0o755 if mode & 0o111 else 0o644)
    elif tarfile.is_tarfile(archive):
        with tarfile.open(archive) as tf:
            for ti in tf.getmembers():
                path = safe(ti.name)
                if ti.isdir():
                    os.makedirs(path, exist_ok=True)
                elif ti.isfile():
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with tf.extractfile(ti) as src, open(path, "wb") as f:
                        shutil.copyfileobj(src, f)
                    set_mode(path, 0o755 if ti.mode & 0o111 else 0o644)
                else:
                    sys.exit("link or special file in {0}: {1}".format(archive, ti.name))
    else:
        sys.exit("not a folder, .zip or .tar.gz: " + archive)


ARCHIVE_RE = re.compile(r"\.(zip|tar\.gz|tgz)$", re.I)


def find_launcher(folder, cli):
    """Folders holding the launcher (any letter case), the shallowest first."""
    found = [(root.count(os.sep), root, f) for root, dirs, files in os.walk(folder)
             for f in files if f.lower() == cli.lower()]
    return sorted(found)


def assessor_root(folder, cli, source):
    """The folder that holds the Assessor launcher. The downloads wrap it in a folder, or in a
    second archive inside the first: those are unpacked too."""
    found = find_launcher(folder, cli)
    other = "Assessor-CLI.sh" if cli.endswith(".bat") else "Assessor-CLI.bat"
    if not found and find_launcher(folder, other):
        sys.exit("{0} holds {1} but no {2}: it is the {3} Assessor, give it as --assessor-{4}".format(
            source, other, cli, *(("Linux", "linux") if cli.endswith(".bat") else
                                  ("Windows", "windows"))))
    if not found:
        nested = sorted(os.path.join(r, f) for r, dirs, files in os.walk(folder)
                        for f in files if ARCHIVE_RE.search(f))
        for i, archive in enumerate(nested):
            unpack(archive, os.path.join(folder, "_nested{0}".format(i)))
        found = find_launcher(folder, cli)
    if not found:
        listing = []
        for r, dirs, files in os.walk(folder):
            dirs.sort()
            rel = os.path.relpath(r, folder)
            if rel.count(os.sep) > 2:
                continue
            listing += [os.path.join(rel, n).replace(os.sep, "/") for n in sorted(dirs + files)]
        sys.exit("no {0} in {1}; it holds (first levels):\n  {2}".format(
            cli, source, "\n  ".join(listing[:60]) or "nothing"))
    depth, root, name = found[0]
    if name != cli and not cli.endswith(".bat"):
        sys.exit("{0}: the launcher is {1}, {2} expected".format(source, name, cli))
    return root


def copy_assessor(src, dest, windows, tmp):
    """The whole Assessor of src (archive or folder) into dest but the files of its license and
    benchmarks folders (those folders and their subfolders stay, empty). Returns the paths left
    out, relative to the Assessor."""
    if not os.path.exists(src):
        sys.exit("Assessor not found: " + src)
    source = src
    if not os.path.isdir(src):
        folder = tempfile.mkdtemp(dir=tmp)
        unpack(src, folder)
        src = folder
    root = assessor_root(src, "Assessor-CLI.bat" if windows else "Assessor-CLI.sh", source)
    # exact names from the folder listing: Cygwin finds java.exe when asked for java
    bindir = os.path.join(root, "jre", "bin")
    names = set(os.listdir(bindir)) if os.path.isdir(bindir) else set()
    want, other = ("java.exe", "java") if windows else ("java", "java.exe")
    if want not in names or other in names:
        sys.exit("{0}: jre/bin holds {1}: not the {2} Assessor".format(
            src, " and ".join(sorted(names & {"java", "java.exe"})) or "no java",
            "Windows" if windows else "Linux"))
    left_out = []
    bench = [n for n in os.listdir(root)
             if n.lower() in MASTER_DIRS and os.path.isdir(os.path.join(root, n))]
    for name in bench:
        for r, dirs, files in os.walk(os.path.join(root, name)):
            dirs.sort()
            left_out += [os.path.relpath(os.path.join(r, f), root) for f in sorted(files)]

    master_dirs = [os.path.abspath(os.path.join(root, n)) for n in bench]

    def ignore(folder, names):
        # in the license and benchmarks folders: the files go, every folder stays
        folder = os.path.abspath(folder)
        if any(folder == d or folder.startswith(d + os.sep) for d in master_dirs):
            return [n for n in names if not os.path.isdir(os.path.join(folder, n))]
        return []
    shutil.copytree(root, dest, ignore=ignore, symlinks=False)
    # modes of the source (archive or disk); on Linux the launcher, the scripts and the JRE are
    # executable whatever the source says (archives made on Windows carry no exec bits)
    for r, dirs, files in os.walk(dest):
        for f in files:
            rel = os.path.relpath(os.path.join(r, f), dest).replace(os.sep, "/")
            mode = 0o755 if mode_of(os.path.join(root, rel)) & 0o111 else 0o644
            if not windows and (rel.endswith(".sh") or rel.startswith("jre/bin/")
                                or rel in ("jre/lib/jspawnhelper", "jre/lib/jexec")):
                mode = 0o755
            set_mode(os.path.join(r, f), mode)
    licensed(dest, [os.path.relpath(os.path.join(r, f), dest)
                    for r, dirs, files in os.walk(dest) for f in files])
    return left_out


def licensed(where, names):
    """Stops the build when a license or benchmark file is among names."""
    bad = [n for n in names if LICENSED_RE.search(n.replace("\\", "/"))]
    if bad:
        sys.exit("license or benchmark file(s) in {0} (the master sends them), remove them and "
                 "build again:\n  {1}".format(where, "\n  ".join(bad[:20])))


def assessor_version(given, src):
    if given:
        if not re.match(r"^\d+(\.\d+)+$", given):
            sys.exit("Assessor version X.Y.Z expected, got: " + given)
        return given
    m = VERSION_RE.search(os.path.basename(os.path.normpath(src)))
    if not m:
        sys.exit("no version in the name {0}: give --assessor-version".format(src))
    return m.group(1)


def walk(folder):
    """(path, name in the package, is a folder) under folder, sorted; names always with /."""
    base = os.path.dirname(folder)
    yield folder, os.path.basename(folder), True
    for root, dirs, files in os.walk(folder):
        dirs.sort()
        for name in dirs:
            p = os.path.join(root, name)
            yield p, os.path.relpath(p, base).replace(os.sep, "/"), True
        for name in sorted(files):
            p = os.path.join(root, name)
            yield p, os.path.relpath(p, base).replace(os.sep, "/"), False


def zip_folder(folder, out):
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for p, name, is_dir in walk(folder):
            if is_dir:
                # every folder has its entry, so empty ones (license, benchmarks) stay
                info = zipfile.ZipInfo(name + "/", (2026, 1, 1, 0, 0, 0))
                info.external_attr = (0o040755 << 16) | 0x10
                zf.writestr(info, b"")
                continue
            info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            info.external_attr = (0o100000 | mode_of(p)) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            with open(p, "rb") as f:
                zf.writestr(info, f.read())


def tar_folder(folder, out):
    with tarfile.open(out, "w:gz") as tf:
        for p, name, is_dir in walk(folder):
            ti = tarfile.TarInfo(name)
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            ti.mtime = 1767225600
            if is_dir:
                ti.type, ti.mode = tarfile.DIRTYPE, 0o755
                tf.addfile(ti)
            else:
                ti.size, ti.mode = os.path.getsize(p), mode_of(p)
                with open(p, "rb") as f:
                    tf.addfile(ti, f)


LINUX_BIN = "var/ossec/active-response/bin/"
WINDOWS_BIN = "Program Files (x86)/ossec-agent/active-response/bin/"
ASSESSOR_LIST = "ciscat-assessor.sha256"
# Assessor paths the bootstrap neither checks nor moves: written on the agent (license and
# benchmarks by the master, reports and logs by CIS-CAT), and the settings
UNCHECKED_RE = re.compile(r"^(license|benchmarks|reports|logs|config)/|^\.bridge-", re.I)


def patch_settings(assessor):
    """exit.on.invalid.signature=false in the Assessor settings (the tailored benchmark is
    unsigned), with the file's own line endings."""
    path = os.path.join(assessor, "config", "assessor-cli.properties")
    text = ""
    if os.path.isfile(path):
        with open(path, "rb") as f:
            text = f.read().decode("utf-8", "replace")
    eol = "\r\n" if "\r\n" in text else "\n"
    lines = [x for x in text.splitlines() if not re.match(r"\s*exit\.on\.invalid\.signature\s*=", x)]
    lines.append("exit.on.invalid.signature=false")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write((eol.join(lines) + eol).encode("utf-8"))
    set_mode(path, 0o644)


def assessor_list(assessor, version):
    """The list of the Assessor's files the bootstrap checks: sha256, two spaces, path."""
    lines = ["# CIS-CAT Pro Assessor {0}: files of the package (sha256  path)".format(version)]
    for p, name, is_dir in walk(assessor):
        rel = name.split("/", 1)[1] if "/" in name else ""
        if is_dir or UNCHECKED_RE.search(rel):
            continue
        lines.append("{0}  {1}".format(sha(p), rel))
    return "\n".join(lines) + "\n"


def final_package(out, entries, windows):
    """A package unpacked as it is (in / or C:\\): entries are (name, file or None for a folder,
    mode, owner, group). Only the folders listed get an entry, so unpacking never changes the
    rights of a folder that is already there (/var, /var/ossec, ...)."""
    if windows:
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, path, mode, owner, group in entries:
                info = zipfile.ZipInfo(name + ("/" if path is None else ""), (2026, 1, 1, 0, 0, 0))
                if path is None:
                    info.external_attr = (0o040000 | mode) << 16 | 0x10
                    zf.writestr(info, b"")
                    continue
                info.external_attr = (0o100000 | mode) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                with open(path, "rb") as f:
                    zf.writestr(info, f.read())
        return
    with tarfile.open(out, "w:gz", format=tarfile.GNU_FORMAT) as tf:
        for name, path, mode, owner, group in entries:
            ti = tarfile.TarInfo(name)
            ti.uid = ti.gid = 0
            ti.uname, ti.gname = owner, group
            ti.mtime = 1767225600
            ti.mode = mode
            if path is None:
                ti.type = tarfile.DIRTYPE
                tf.addfile(ti)
            else:
                ti.size = os.path.getsize(path)
                with open(path, "rb") as f:
                    tf.addfile(ti, f)


def assessor_entries(assessor, prefix):
    """Entries of the Assessor folder under prefix (the Assessor folder itself root only)."""
    entries = []
    for p, name, is_dir in walk(assessor):
        rel = name.split("/", 1)[1] if "/" in name else ""
        target = prefix + ("/" + rel if rel else "")
        if is_dir:
            entries.append((target, None, 0o700 if not rel else 0o755, "root", "root"))
        else:
            entries.append((target, p, mode_of(p), "root", "root"))
    return entries


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--plugin", required=True, help="file name of the dashboard plugin zip")
    ap.add_argument("--plugin-sha256", required=True, help="sha256 of the plugin zip")
    ap.add_argument("--out", default=os.path.join(HERE, "out"))
    ap.add_argument("--assessor-windows", help="CIS-CAT Pro Assessor for Windows (zip or folder)")
    ap.add_argument("--assessor-linux",
                    help="CIS-CAT Pro Assessor for Linux (zip, tar.gz or folder)")
    ap.add_argument("--assessor-version", help="version of both Assessors, e.g. 4.64.0")
    ap.add_argument("--assessor-version-windows", help="version of the Windows Assessor")
    ap.add_argument("--assessor-version-linux", help="version of the Linux Assessor")
    ap.add_argument("--master-keys", help="folder with the master's ciscat-manifest.pub and "
                    "ciscat-manifest.pub.xml, pinned in the final agent packages")
    a = ap.parse_args()
    if not re.match(r"^[0-9a-f]{64}$", a.plugin_sha256):
        sys.exit("--plugin-sha256: 64 hex characters expected")
    wver = lver = None
    if a.assessor_windows:
        wver = assessor_version(a.assessor_version_windows or a.assessor_version,
                                a.assessor_windows)
    if a.assessor_linux:
        lver = assessor_version(a.assessor_version_linux or a.assessor_version, a.assessor_linux)
    v = version()
    subs = {"VERSION": v, "WAZUH": WAZUH}
    out = os.path.abspath(a.out)
    shutil.rmtree(out, ignore_errors=True)
    work = os.path.join(out, "work")
    tmp = os.path.join(out, "tmp")
    os.makedirs(tmp)
    removed = {}
    keys = None
    if a.master_keys:
        keys = [os.path.join(a.master_keys, n) for n in ("ciscat-manifest.pub",
                                                          "ciscat-manifest.pub.xml")]
        for k in keys:
            if not os.path.isfile(k):
                sys.exit("--master-keys: {0} not found".format(k))

    # bridge installer (embeds bin/, agent/, rules/)
    subprocess.run([sys.executable, os.path.join(BRIDGE, "installer", "build.py")], check=True,
                   stdout=subprocess.DEVNULL)
    installer = os.path.join(BRIDGE, "dist", "ciscat-bridge-install-{0}.sh".format(v))

    # master
    m = os.path.join(work, "master")
    os.makedirs(m)
    shutil.copy(installer, m)
    set_mode(os.path.join(m, os.path.basename(installer)), 0o755)
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
    sums(w)
    finals = []
    if a.assessor_windows:
        wa = os.path.join(tmp, "windows", "Assessor")
        removed["windows"] = copy_assessor(a.assessor_windows, wa, True, tmp)
        patch_settings(wa)
        write(os.path.join(wa, ".bridge-assessor-version"), wver + "\r\n")
        wlist = os.path.join(tmp, "windows", ASSESSOR_LIST)
        write(wlist, assessor_list(wa, wver).replace("\n", "\r\n"))
        entries = [("CIS", None, 0o755, "root", "root")] + assessor_entries(wa, "CIS/Assessor")
        entries += [(WINDOWS_BIN + n, os.path.join(AGENT, n), 0o644, "root", "root")
                    for n in ("ciscat-assessment.cmd", "ciscat-bootstrap.ps1")]
        entries.append((WINDOWS_BIN + ASSESSOR_LIST, wlist, 0o644, "root", "root"))
        if keys:
            entries.append((WINDOWS_BIN + "ciscat-manifest.pub.xml", keys[1], 0o644, "root", "root"))
        finals.append(("windows", os.path.join(out, "ciscat-agent-windows-{0}-assessor-{1}.zip"
                                               .format(v, wver)), entries))

    # Linux agent
    li = os.path.join(work, "agent-linux")
    src = os.path.join(HERE, "agent-linux")
    boot = os.path.join(BRIDGE, "bin", "ciscat-bootstrap.sh")
    lsubs = dict(subs, BOOTSTRAP_SHA=sha(boot), BOOTSTRAP_B64=b64(boot, lines=True))
    for name, mode in (("install-linux-agent.sh", 0o755), ("ciscat-e2e-linux.sh", 0o755),
                       ("README.txt", 0o644)):
        write(os.path.join(li, name), render(os.path.join(src, name), lsubs), mode)
    sums(li)
    if a.assessor_linux:
        la = os.path.join(tmp, "linux", "Assessor")
        removed["linux"] = copy_assessor(a.assessor_linux, la, False, tmp)
        patch_settings(la)
        write(os.path.join(la, ".bridge-assessor-version"), lver + "\n")
        llist = os.path.join(tmp, "linux", ASSESSOR_LIST)
        write(llist, assessor_list(la, lver))
        entries = [("opt/ciscat", None, 0o755, "root", "root")]
        entries += assessor_entries(la, "opt/ciscat/Assessor")
        entries += [("var/lib/wazuh-ciscat", None, 0o700, "root", "root"),
                    (LINUX_BIN + "ciscat-bootstrap.sh", boot, 0o750, "root", "wazuh"),
                    (LINUX_BIN + ASSESSOR_LIST, llist, 0o640, "root", "wazuh")]
        if keys:
            entries.append(("var/lib/wazuh-ciscat/ciscat-manifest.pub", keys[0], 0o644, "root",
                            "root"))
        finals.append(("linux", os.path.join(out, "ciscat-agent-linux-{0}-assessor-{1}.tar.gz"
                                             .format(v, lver)), entries))

    results = [(m, os.path.join(out, "ciscat-master-{0}.zip".format(v)), zip_folder)]
    if not wver:
        results.append((w, os.path.join(out, "ciscat-agent-windows-{0}.zip".format(v)),
                        zip_folder))
    if not lver:
        results.append((li, os.path.join(out, "ciscat-agent-linux-{0}.tar.gz".format(v)),
                        tar_folder))
    for platform, path, entries in finals:
        results.append((entries, path, lambda e, p, w=(platform == "windows"):
                        final_package(p, e, w)))
        # the end-to-end test of the platform, next to its final package
        e2e = os.path.join(w if platform == "windows" else li, "ciscat-e2e-{0}.{1}".format(
            platform, "ps1" if platform == "windows" else "sh"))
        shutil.copy(e2e, out)
        set_mode(os.path.join(out, os.path.basename(e2e)), mode_of(e2e))
    lines = []
    for folder, path, pack in results:
        pack(folder, path)
        # what was packed, read back from the package itself
        if path.endswith(".zip"):
            with zipfile.ZipFile(path) as zf:
                names = [n for n in zf.namelist() if not n.endswith("/")]
        else:
            with tarfile.open(path) as tf:
                names = [m.name for m in tf.getmembers() if m.isfile()]
        licensed(os.path.basename(path), [n.split("/Assessor/", 1)[1] for n in names
                                          if "/Assessor/" in n])
        lines.append("{0}  {1}".format(sha(path), os.path.basename(path)))
    shutil.rmtree(work)
    shutil.rmtree(tmp)
    write(os.path.join(out, "SHA256SUMS"), "\n".join(lines) + "\n")
    for platform, files in sorted(removed.items()):
        # record of what the package leaves out of the CIS download (no content, names only)
        write(os.path.join(out, "assessor-left-out-{0}.txt".format(platform)),
              "".join(f.replace("\\", "/") + "\n" for f in files))
    print("\n".join(lines))
    for platform, files in sorted(removed.items()):
        print("{0} Assessor: {1} license and benchmark file(s) left out: "
              "assessor-left-out-{0}.txt".format(platform, len(files)))
    if removed:
        print("contains CIS-CAT Pro (licensed): internal release store only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
