#!/usr/bin/env python3
"""Puts together the single bundle for a Wazuh master: master package, dashboard plugin, CIS
benchmarks (from the CIS-CAT Pro downloads), license, optional configuration of another master,
final agent packages, install-prod.sh. Run by build-prod-bundle.sh after the packages are built.

  python3 prod_bundle.py --windows ZIP --linux ZIP --release DIR --extras DIR --version X.Y.Z
                         --plugin-sha256 SHA --out FILE
"""
import argparse
import hashlib
import io
import os
import re
import shutil
import sys
import tarfile
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
# build.py: next to this folder in the repository, in ciscat-bridge/packaging in the kit
for p in (os.path.join(HERE, "ciscat-bridge", "packaging"), os.path.dirname(HERE)):
    if os.path.isfile(os.path.join(p, "build.py")):
        sys.path.insert(0, p)
        break
import build  # noqa: E402  (unpack, assessor_root)


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def benchmarks(download, windows, tmp):
    """The files of the Assessor's benchmarks folder of a CIS download: {name: path}."""
    folder = tempfile.mkdtemp(dir=tmp)
    if os.path.isdir(download):
        folder = download
    else:
        build.unpack(download, folder)
    root = build.assessor_root(folder, "Assessor-CLI.bat" if windows else "Assessor-CLI.sh",
                               download)
    out = {}
    bench = [n for n in os.listdir(root) if n.lower() == "benchmarks"]
    for b in bench:
        for r, dirs, files in os.walk(os.path.join(root, b)):
            for f in files:
                out.setdefault(f, []).append(os.path.join(r, f))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    for a in ("windows", "linux", "release", "extras", "version", "plugin_sha256", "out"):
        ap.add_argument("--" + a.replace("_", "-"), required=True)
    a = ap.parse_args()
    v = a.version
    tmp = tempfile.mkdtemp()
    try:
        files = {}  # name in the bundle -> (source path, mode)

        # master package and final agent packages, as built
        master = os.path.join(a.release, "ciscat-master-{0}.zip".format(v))
        if not os.path.isfile(master):
            sys.exit("{0} not found: build the packages first".format(master))
        files["ciscat-master-{0}.zip".format(v)] = (master, 0o644)
        agents = sorted(n for n in os.listdir(a.release) if re.match(
            r"ciscat-agent-(linux|windows)-.*-assessor-|ciscat-e2e-|assessor-left-out-", n))
        if len([n for n in agents if n.startswith("ciscat-agent-")]) != 2:
            sys.exit("the two final agent packages are not in {0}".format(a.release))
        for n in agents:
            p = os.path.join(a.release, n)
            # the agents take the master's key from their group files: none in the packages
            if n.endswith(".zip"):
                names = zipfile.ZipFile(p).namelist()
            elif n.endswith(".tar.gz"):
                with tarfile.open(p) as t:
                    names = t.getnames()
            else:
                names = []
            if [x for x in names if x.endswith(("ciscat-manifest.pub", "ciscat-manifest.pub.xml"))]:
                sys.exit("{0} pins a master key: remove ciscat-manifest.pub* next to the downloads "
                         "and build again (the agents take the key from the master)".format(n))
            files["agents/" + n] = (p, 0o755 if n.endswith(".sh") else 0o644)

        # dashboard plugin, checked
        plugins = [n for n in os.listdir(a.extras)
                   if re.match(r"wazuh-dashboard-plugins_wazuh_.*\.zip$", n)]
        plugin = None
        for n in plugins:
            if sha(os.path.join(a.extras, n)) == a.plugin_sha256:
                plugin = n
        if plugins and not plugin:
            sys.exit("dashboard plugin {0}: sha256 is not {1} (the plugin of this release)".format(
                ", ".join(plugins), a.plugin_sha256))
        if plugin:
            files[plugin] = (os.path.join(a.extras, plugin), 0o644)
        else:
            print("   no dashboard plugin next to the downloads: the bundle leaves the dashboard as it is")

        # CIS benchmarks of both downloads, one folder
        found = {}
        for download, windows in ((a.windows, True), (a.linux, False)):
            for name, paths in benchmarks(download, windows, tmp).items():
                found.setdefault(name, []).extend(paths)
        for name, paths in sorted(found.items()):
            if len({sha(p) for p in paths}) > 1:
                sys.exit("benchmark {0} differs between the two downloads".format(name))
            files["benchmarks/" + name] = (paths[0], 0o644)
        nb = len(found)

        # license and configuration of another master, when given
        lic = os.path.join(a.extras, "license.xml")
        if os.path.isfile(lic):
            files["license/license.xml"] = (lic, 0o600)
        configs = sorted(n for n in os.listdir(a.extras) if re.match(r"ciscat-config-.*\.tgz$", n))
        if configs:
            c = configs[-1]
            files[c] = (os.path.join(a.extras, c), 0o600)
            if os.path.isfile(os.path.join(a.extras, c + ".sha256")):
                files[c + ".sha256"] = (os.path.join(a.extras, c + ".sha256"), 0o644)

        # install script and checksums
        with open(os.path.join(HERE, "install-prod.sh"), encoding="utf-8") as f:
            script = f.read().replace("@VERSION@", v)
        sp = os.path.join(tmp, "install-prod.sh")
        with open(sp, "w", encoding="utf-8", newline="\n") as f:
            f.write(script)
        files["install-prod.sh"] = (sp, 0o755)
        sums = "".join("{0}  {1}\n".format(sha(p), n) for n, (p, m) in sorted(files.items()))
        spath = os.path.join(tmp, "SHA256SUMS")
        with open(spath, "w", newline="\n") as f:
            f.write(sums)
        files["SHA256SUMS"] = (spath, 0o644)

        # the tar: modes and owners set here, not read from the disk (same on Windows)
        top = "ciscat-prod-{0}".format(v)
        with tarfile.open(a.out, "w:gz", format=tarfile.GNU_FORMAT) as t:
            dirs = sorted({os.path.dirname(n) for n in files} - {""})
            for d in [""] + dirs:
                ti = tarfile.TarInfo(top + ("/" + d if d else ""))
                ti.type, ti.mode, ti.mtime = tarfile.DIRTYPE, 0o700 if not d else 0o755, 1767225600
                ti.uname = ti.gname = "root"
                t.addfile(ti)
            for n, (p, mode) in sorted(files.items()):
                ti = tarfile.TarInfo(top + "/" + n)
                ti.size, ti.mode, ti.mtime = os.path.getsize(p), mode, 1767225600
                ti.uname = ti.gname = "root"
                with open(p, "rb") as f:
                    t.addfile(ti, f)
        print("   bundle: {0}".format(a.out))
        print("     master package, {0}, {1} benchmark file(s), {2}, {3}, {4} agent file(s)".format(
            "dashboard plugin" if plugin else "no plugin", nb,
            "license" if os.path.isfile(lic) else "no license",
            "configuration " + configs[-1] if configs else "no configuration import",
            len(agents)))
        print("   sha256 {0}".format(sha(a.out)))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
