"""CIS XCCDF benchmarks, parsed as XML: profiles, rules and their texts.

One parser for every script of the bridge that reads a benchmark (discovery, benchmark sheets,
custom XCCDF, SCA policy). Elements are matched by local name, so the xccdf: prefix, the default
namespace and XCCDF 1.1/1.2 all read the same. A DOCTYPE is refused: CIS benchmarks have none,
and without it no entity can be declared or expanded.

The byte range of each Profile element is kept, so a tailored copy of a profile can be inserted
into the original text without rewriting the rest of the document.

Stdlib only; runs on Python 3.6+.
"""
import os
import re
import xml.etree.ElementTree as ET
from xml.parsers import expat

PROFILE_PREFIX = "xccdf_org.cisecurity.benchmarks_profile_"
XHTML_NS = "http://www.w3.org/1999/xhtml"
RULE_NUM_RE = re.compile(r"_rule_([0-9.]+)_")
CONTROL_V8_RE = re.compile(r"http://cisecurity\.org/20-cc/v8\.0/control/(\d+)/subcontrol/(\d+)")
_CACHE = {}
_CACHE_SIZE = 4


class XccdfError(ValueError):
    """A file that is not a well-formed XCCDF benchmark, or that the bridge refuses to read."""


def local(tag):
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def namespace(tag):
    return tag[1:].split("}", 1)[0] if isinstance(tag, str) and tag.startswith("{") else ""


def rule_number(idref):
    """CIS recommendation number of a rule id (xccdf_..._rule_1.1.1_Title -> 1.1.1), or None."""
    m = RULE_NUM_RE.search(idref or "")
    return m.group(1) if m else None


def collapse(text):
    return re.sub(r"\s+", " ", text).strip()


def text_of(elem):
    """All the text of an element (markup removed), whitespace collapsed."""
    return collapse("".join(elem.itertext())) if elem is not None else ""


def _parse(raw):
    """(root element, {id(Profile element): (start, end) byte offsets}) of an XML document."""
    builder = ET.TreeBuilder()
    parser = expat.ParserCreate(namespace_separator="}")
    parser.buffer_text = True
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    spans, starts = {}, []

    def refuse(*_):
        raise XccdfError("DOCTYPE and entity declarations are not accepted")

    def tag_of(name):
        return "{" + name if "}" in name else name

    def start(name, attrs):
        tag = tag_of(name)
        starts.append(parser.CurrentByteIndex)
        builder.start(tag, {tag_of(k): v for k, v in attrs.items()})

    def end(name):
        elem = builder.end(tag_of(name))
        begin = starts.pop()
        if local(elem.tag) == "Profile":
            at = parser.CurrentByteIndex
            close = raw.find(b">", at if raw.startswith(b"</", at) else begin) + 1
            spans[id(elem)] = (begin, close)

    parser.StartDoctypeDeclHandler = refuse
    parser.EntityDeclHandler = refuse
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = builder.data
    try:
        parser.Parse(raw, True)
    except expat.ExpatError as exc:
        raise XccdfError("not well-formed XML: {0}".format(exc))
    return builder.close(), spans


class Benchmark:
    def __init__(self, raw):
        # text-mode reads of the benchmark used to translate line ends: keep that, so the custom
        # XCCDF built from this text is the same
        self.raw = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        self.root, self._spans = _parse(self.raw)
        if local(self.root.tag) != "Benchmark":
            raise XccdfError("not an XCCDF benchmark (root element {0})".format(local(self.root.tag)))
        self.id = self.root.get("id", "")
        version = self.child(self.root, "version")
        self.version = version.text.strip() if version is not None and version.text else ""
        self.profiles = [e for e in self.root if local(e.tag) == "Profile"]
        self.rules = {}
        for e in self.root.iter():
            if local(e.tag) == "Rule" and e.get("id"):
                self.rules.setdefault(e.get("id"), e)

    @staticmethod
    def child(elem, name):
        """First child element of that local name, or None."""
        for c in elem:
            if local(c.tag) == name:
                return c
        return None

    @staticmethod
    def first(elem, name):
        """First descendant element of that local name, or None."""
        for e in elem.iter():
            if e is not elem and local(e.tag) == name:
                return e
        return None

    # --- profiles ---------------------------------------------------------------------------
    def profile(self, profile_id):
        for p in self.profiles:
            if p.get("id") == profile_id:
                return p
        return None

    def profile_ids(self):
        return [p.get("id", "") for p in self.profiles]

    @staticmethod
    def selects(profile):
        """[(idref, selected)] of a profile's <select> elements, in document order."""
        return [(s.get("idref", ""), s.get("selected") in ("true", "1"))
                for s in profile if local(s.tag) == "select"]

    def selected(self, profile):
        return [idref for idref, sel in self.selects(profile) if sel]

    def profile_text(self, profile):
        """The profile element exactly as written in the document."""
        start, end = self._spans[id(profile)]
        return self.raw[start:end].decode("utf-8")

    def profiles_end(self):
        """Byte offset just after the last profile (where tailored profiles are inserted)."""
        return self._spans[id(self.profiles[-1])][1]

    # --- rules ------------------------------------------------------------------------------
    def rule_title(self, idref):
        rule = self.rules.get(idref)
        return text_of(self.child(rule, "title")) if rule is not None else ""

    @staticmethod
    def is_manual(rule):
        """A rule without any <check> or <complex-check> (no OVAL) is assessed by hand."""
        return not any(local(e.tag) in ("check", "complex-check") for e in rule.iter())

    def manual_numbers(self):
        return {n for n in (rule_number(i) for i, r in self.rules.items() if self.is_manual(r)) if n}

    def rule_prose(self, idref, name):
        """Cleaned text of the rule's description, rationale or fixtext (see clean_xhtml)."""
        rule = self.rules.get(idref)
        elem = self.first(rule, name) if rule is not None else None
        return clean_xhtml(elem) if elem is not None else ""

    def rule_controls_v8(self, idref):
        """CIS Controls v8 safeguards of a rule ("control.safeguard"), in document order."""
        rule = self.rules.get(idref)
        out = []
        for e in (rule.iter() if rule is not None else ()):
            for k, v in e.attrib.items():
                m = CONTROL_V8_RE.fullmatch(v) if local(k) == "controlURI" else None
                if m and "{0}.{1}".format(*m.groups()) not in out:
                    out.append("{0}.{1}".format(*m.groups()))
        return out

    def family_titles(self):
        """Titles of the top-level groups by number, e.g. {"1": "Initial Setup"}; sub-groups
        (<N>.<M>) are skipped. '|' becomes '/': it separates fields in the manager's wazuh-db
        messages."""
        out = {}
        for g in self.root.iter():
            if local(g.tag) != "Group":
                continue
            m = re.match(r".*_group_(\d+)_", g.get("id", ""))
            if not m or m.group(1) in out:
                continue
            title = text_of(self.child(g, "title")).replace("|", "/")
            if title:
                out[m.group(1)] = title
        return out


def clean_xhtml(elem):
    """Single-line text of CIS XHTML prose (description, rationale, fixtext): paragraphs, line
    breaks and list items separate words, links read "text (href)", markup is dropped."""
    parts = []

    def walk(e, top):
        name = local(e.tag) if namespace(e.tag) == XHTML_NS else None
        if name == "br":
            parts.append("\n")
        elif name == "li" and not e.attrib:
            parts.append("\n- ")
        parts.append(e.text or "")
        for c in e:
            walk(c, False)
        if name == "a" and e.get("href") is not None:
            parts.append(" ({0})".format(e.get("href")))
        elif name == "p":
            parts.append("\n")
        if not top:
            parts.append(e.tail or "")

    walk(elem, True)
    lines = [re.sub(r"[ \t]+", " ", ln).strip() for ln in "".join(parts).split("\n")]
    return " ".join(ln for ln in lines if ln).strip()


def load(path):
    """The parsed benchmark at path (kept for the next call while the file is unchanged)."""
    st = os.stat(path)
    key = (os.path.abspath(path), st.st_mtime_ns, st.st_size)
    if key not in _CACHE:
        with open(path, "rb") as f:
            bench = Benchmark(f.read())
        while len(_CACHE) >= _CACHE_SIZE:
            _CACHE.pop(next(iter(_CACHE)))
        _CACHE[key] = bench
    return _CACHE[key]
