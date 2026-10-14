#!/usr/bin/env python3
"""pci-keep.py - CIS-CAT bridge 2.3.1: carries the site's PCI DSS reporting from the Wazuh plugin
it replaces (OLD) into the newly installed one (NEW). Run by align-prod.sh as root:
  python3 pci-keep.py <old plugin folder> <new plugin folder>

Taken from OLD as they are (the new plugin did not change these files):
  server/lib/reporting/pci-request.js, extended-information.js and
  summary-tables-definitions/{agents,overview}/index.js       PCI DSS report sections and texts
  public/assets/custom/                                         report logo and custom images
Made again on NEW (the new plugin changed these files too):
  server/lib/reporting/printer.js        no time range and filters band, as in OLD
  server/controllers/wazuh-reporting.js  PCI DSS PDF without the panels OLD leaves out
  target/public/*.js                      PCI DSS dashboard panels of OLD; the report leaves out
                                          the same panels as OLD
Every change must apply exactly once, else nothing is written and it exits 1 (the caller puts
OLD back). Prints RESULT: OK.
"""
import os
import re
import shutil
import subprocess
import sys

LEFT_OUT = ["Top 10 PCI DSS requirements", "Top 10 agents by alerts count",
            "Top 10 agents by events count", "Last alerts", "Last events", "Requirements by agent"]
COPY = ["server/lib/reporting/pci-request.js", "server/lib/reporting/extended-information.js",
        "server/lib/reporting/summary-tables-definitions/agents/index.js",
        "server/lib/reporting/summary-tables-definitions/overview/index.js"]
PANELS = ["Wazuh-App-Overview-PCI-DSS-requirements", "Wazuh-App-Overview-PCI-DSS-Agents",
          "Wazuh-App-Overview-PCI-DSS-Requirements-Agents-heatmap",
          "Wazuh-App-Overview-PCI-DSS-Requirements-by-agent"]
NODE = "/usr/share/wazuh-dashboard/node/bin/node"


def fail(msg):
    print("STOP: " + msg)
    sys.exit(1)


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def once(text, pattern, repl, what):
    new, n = re.subn(pattern, repl, text, flags=re.S)
    if n != 1:
        fail("{0}: found {1} time(s), expected 1".format(what, n))
    return new


def arrow_body(text, start):
    """The balanced '(...)' of 'indexPatternId=>(' at or after start."""
    j = text.index("=>(", start) + 2
    depth, quote, k = 0, None, j
    while k < len(text):
        c = text[k]
        if quote:
            if c == "\\":
                k += 1
            elif c == quote:
                quote = None
        elif c in "\"'`":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return j, k + 1
        k += 1
    fail("unbalanced panel definition")


def panel_sites(text, panel_id):
    return [m.start() for m in re.finditer(r'=indexPatternId=>\(\{id:"' + re.escape(panel_id) + '"', text)]


def main():
    if len(sys.argv) != 3:
        fail("usage: pci-keep.py <old plugin folder> <new plugin folder>")
    old, new = sys.argv[1], sys.argv[2]
    out = {}  # path in NEW -> content to write

    for rel in COPY:
        if not os.path.isfile(os.path.join(old, rel)):
            fail("old plugin has no " + rel)
        if not os.path.isfile(os.path.join(new, rel)):
            fail("new plugin has no " + rel)
        out[rel] = read(os.path.join(old, rel))

    rel = "server/lib/reporting/printer.js"
    out[rel] = once(read(os.path.join(new, rel)),
                    r"(addTimeRangeAndFilters\s*\(\s*from\s*,\s*to\s*,\s*filters\s*,\s*timeZone\s*\)\s*\{)",
                    r"\1\n    return; // this site's reports have no time range and filters band\n",
                    "printer.js addTimeRangeAndFilters")

    rel = "server/controllers/wazuh-reporting.js"
    titles = ", ".join("'{0}'".format(t) for t in LEFT_OUT)
    out[rel] = once(read(os.path.join(new, rel)),
                    r"printer\.addVisualizations\(\s*array\s*,\s*agents\s*,\s*moduleID\s*\)",
                    "printer.addVisualizations(moduleID === 'pci' && Array.isArray(array) ? "
                    "array.filter(item => ![" + titles + "].includes(String(item && item.title ? "
                    "item.title : '').trim())) : array, agents, moduleID)",
                    "wazuh-reporting.js addVisualizations")

    pub_old = os.path.join(old, "target", "public")
    pub_new = os.path.join(new, "target", "public")
    olds = {n: read(os.path.join(pub_old, n)) for n in os.listdir(pub_old) if n.endswith(".js")}
    news = {n: read(os.path.join(pub_new, n)) for n in os.listdir(pub_new) if n.endswith(".js")}
    for panel in PANELS:
        src = [(n, i) for n, t in olds.items() for i in panel_sites(t, panel)]
        if not src:
            fail("old plugin has no panel " + panel)
        n, i = src[0]
        a, b = arrow_body(olds[n], i)
        body = olds[n][a:b]
        dst = [(m, k) for m, t in news.items() for k in panel_sites(t, panel)]
        if len(dst) != 1:
            fail("panel {0}: found {1} time(s) in the new plugin, expected 1".format(panel, len(dst)))
        m, k = dst[0]
        a, b = arrow_body(news[m], k)
        news[m] = news[m][:a] + body + news[m][b:]
    titles = ",".join('"{0}"'.format(t) for t in LEFT_OUT)
    hits = [n for n, t in news.items() if t.count("async getVisualizationsFromDOM(){") == 1]
    if len(hits) != 1 or sum(t.count("async getVisualizationsFromDOM(){") for t in news.values()) != 1:
        fail("report service getVisualizationsFromDOM: not found once in the new plugin")
    news[hits[0]] = news[hits[0]].replace(
        "async getVisualizationsFromDOM(){",
        "async getVisualizationsFromDOM(){return(await this.siteAllVisualizationsFromDOM()).filter("
        "v=>![" + titles + "].includes((v.title||\"\").trim()))}"
        "async siteAllVisualizationsFromDOM(){", 1)
    for n, t in news.items():
        if t != read(os.path.join(pub_new, n)):
            out[os.path.join("target", "public", n)] = t

    # syntax check of every changed script before anything is written
    node = NODE if os.path.exists(NODE) else shutil.which("node")
    tmpdir = os.path.join(new, ".pci-keep-check")
    os.makedirs(tmpdir, exist_ok=True)
    try:
        for i, (rel, text) in enumerate(out.items()):
            if node:
                probe = os.path.join(tmpdir, "{0}.js".format(i))
                with open(probe, "w", encoding="utf-8") as f:
                    f.write(text)
                r = subprocess.run([node, "--check", probe], stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, universal_newlines=True)
                if r.returncode != 0:
                    fail("{0}: not valid JavaScript after the change:\n{1}".format(rel, r.stdout[-800:]))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    if not node:
        print("   (no node found: syntax check skipped)")

    for rel, text in out.items():
        path = os.path.join(new, rel)
        st = os.stat(path)
        with open(path + ".pci-new", "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(path + ".pci-new", st.st_mode & 0o7777)
        os.replace(path + ".pci-new", path)
        print("   " + rel)
    custom = os.path.join(old, "public", "assets", "custom")
    if os.path.isdir(custom):
        dest = os.path.join(new, "public", "assets", "custom")
        if os.path.isdir(dest):
            shutil.rmtree(dest)
        shutil.copytree(custom, dest)
        print("   public/assets/custom (report logo and images)")
    print("RESULT: OK")


if __name__ == "__main__":
    main()
