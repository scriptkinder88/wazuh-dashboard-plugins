"""Which Wazuh the bridge runs on (4.x or 5.0), and the manager paths that depend on it.

Wazuh 5.0 installs the manager in /var/wazuh-manager (user and group wazuh-manager, config
etc/wazuh-manager.conf); 4.x in /var/ossec (user and group wazuh, config etc/ossec.conf).
Agents keep /var/ossec on both. CISCAT_PLATFORM=4|5 overrides the detection (tests, or a host
where both trees exist during a migration).

Stdlib only; runs on Python 3.6+.
"""
import os
import re

MANAGER_HOME = {4: "/var/ossec", 5: "/var/wazuh-manager"}
MANAGER_CONF = {4: "etc/ossec.conf", 5: "etc/wazuh-manager.conf"}
OWNER = {4: ("wazuh", "wazuh"), 5: ("wazuh-manager", "wazuh-manager")}

# Wazuh 5.0: runs are requested by writing trigger documents into this data stream; one Alerting
# monitor per action matches them and calls the Active Response channel of the same name.
TRIGGER_STREAM = "wazuh-findings-v5-ciscat"
TRIGGER_PATTERN = TRIGGER_STREAM + "*"
# action name -> executable run by the agent from active-response/bin (same scripts as on 4.x)
AR_ACTIONS = {
    "ciscat-bootstrap-linux": "ciscat-bootstrap.sh",
    "ciscat-refresh-linux": "ciscat-refresh.sh",
    "ciscat-bootstrap-windows": "ciscat-bootstrap.cmd",
    "ciscat-assessment-windows": "ciscat-assessment.cmd",
}
DEFAULT_AR = {
    4: {"linux": {"ar_bootstrap": "!ciscat-bootstrap-linux0", "ar_refresh": "!ciscat-refresh-linux0"},
        "windows": {"ar_bootstrap": "!ciscat-bootstrap0", "ar_assessment": "!ciscat-assessment0"}},
    5: {"linux": {"ar_bootstrap": "ciscat-bootstrap-linux", "ar_refresh": "ciscat-refresh-linux"},
        "windows": {"ar_bootstrap": "ciscat-bootstrap-windows",
                    "ar_assessment": "ciscat-assessment-windows"}},
}
# 4.x Active Response commands -> 5.0 action names
LEGACY_AR = {
    "!ciscat-bootstrap-linux0": "ciscat-bootstrap-linux",
    "!ciscat-refresh-linux0": "ciscat-refresh-linux",
    "!ciscat-bootstrap0": "ciscat-bootstrap-windows",
    "!ciscat-assessment0": "ciscat-assessment-windows",
}
AR_FIELDS = ("ar_bootstrap", "ar_refresh", "ar_assessment")


def detect(root="/"):
    """4 or 5."""
    forced = os.environ.get("CISCAT_PLATFORM", "").strip()
    if forced in ("4", "5"):
        return int(forced)
    if forced:
        raise ValueError("CISCAT_PLATFORM must be 4 or 5, not {0!r}".format(forced))
    return 5 if os.path.isdir(os.path.join(root, MANAGER_HOME[5].lstrip("/"))) else 4


def manager_home(platform):
    return MANAGER_HOME[platform]


def shared_dir(platform):
    return MANAGER_HOME[platform] + "/etc/shared"


def manager_conf(platform):
    return MANAGER_HOME[platform] + "/" + MANAGER_CONF[platform]


def owner(platform):
    """(user, group) of the files the manager distributes from etc/shared."""
    return OWNER[platform]


def is_worker(conf_text, platform):
    """True for a cluster worker. On 4.x only an enabled cluster counts; on 5.0 every manager is a
    cluster node and the role is <cluster><node_type> (master by default)."""
    cluster = re.search(r"<cluster>(.*?)</cluster>", conf_text or "", re.S)
    if not cluster or not re.search(r"<node_type>\s*worker\s*</node_type>", cluster.group(1)):
        return False
    if platform == 4:
        return bool(re.search(r"<disabled>\s*no\s*</disabled>", cluster.group(1)))
    return True


def ar_action(value, family, field):
    """The 5.0 action name for an OS entry's ar_* value: 4.x commands are mapped, a value in the
    4.x command form ('!name') that is not a bridge command falls back to the default of the
    family, any other value is taken as an action name the site set up itself."""
    if value in LEGACY_AR:
        return LEGACY_AR[value]
    if not value or value.startswith("!"):
        return DEFAULT_AR[5].get(family, {}).get(field, value)
    return value


def ar_entry_for(cfg, platform):
    """Copy of an OS entry with its Active Response values for the platform."""
    if platform != 5:
        return cfg
    out = dict(cfg)
    for field in AR_FIELDS:
        if field in out:
            out[field] = ar_action(out[field], out.get("family", "linux"), field)
    return out
