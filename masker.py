"""
masker.py
---------
Applies org-specific masking to a single BloodHound CE JSON object.

Strategy
~~~~~~~~
Rather than walking an arbitrary JSON tree (fragile), we handle each
*named field* explicitly, because the CE schema is well-defined and we
know exactly which fields carry org-specific data.

Every substitution goes through the MappingStore so tokens are
consistent across files and runs.

SID handling
~~~~~~~~~~~~
Standard domain SID:  S-1-5-21-<A>-<B>-<C>-<RID>
  -> mask the A-B-C triple, preserve everything else.

Domain-prefixed SID:  TRAINING.LOCAL-S-1-5-32-544
  -> only mask the domain prefix; the S-1-5-XX suffix is well-known.

Compound (computer-local) SID:  S-1-5-21-<A>-<B>-<C>-<computer_rid>-<local_rid>
  -> mask A-B-C only; both trailing numbers are preserved.

SPN handling
~~~~~~~~~~~~
All SPN formats are handled:
  service/host
  service/host:port
  service/host:instance_name
  service/host/realm_or_domain
  service/host/short_name
  UUID.subdomain/host
  kadmin/changepw   <- well-known, skip

The service label is NEVER masked (it identifies the protocol).
Only the host and any domain/realm components are masked.
"""

import re
import copy
from typing import Any, Optional

from mapping import MappingStore
from safelist import (
    is_default_group,
    is_builtin_domain_prefixed_sid,
    DEFAULT_GROUP_NAMES,
    TIER_ZERO_NAMED_ASSETS,
)
from token_gen import (
    TYPE_DOMAIN, TYPE_USER, TYPE_COMPUTER, TYPE_GROUP,
    TYPE_GPO, TYPE_OU, TYPE_CA, TYPE_CERTTEMPLATE, TYPE_CONTAINER,
)

# ---------------------------------------------------------------------------
# Regex patterns compiled once
# ---------------------------------------------------------------------------

_RE_DOMAIN_SID = re.compile(
    r'^(S-1-5-21-)(\d+-\d+-\d+)((?:-\d+)*)$', re.IGNORECASE
)
_RE_DOMAIN_PREFIXED_SID = re.compile(
    # Capture the masked-able domain prefix and the ENTIRE SID body verbatim.
    # The body (e.g. "S-1-1-0", "S-1-5-11", "S-1-5-32-544") is preserved exactly
    # so the authority number is never altered.
    r'^([A-Z0-9][A-Z0-9.\-]*?\.[A-Z]{2,})-(S-1-[0-9].*)$', re.IGNORECASE
)
_RE_FQDN = re.compile(
    r'^([A-Z0-9][A-Z0-9\-]*?)\.([A-Z0-9][A-Z0-9.\-]*\.[A-Z]{2,})$',
    re.IGNORECASE,
)
_RE_AT_DOMAIN = re.compile(
    r'^(.+?)@([A-Z0-9][A-Z0-9.\-]*\.[A-Z]{2,})$', re.IGNORECASE
)
_RE_DN_COMPONENT = re.compile(r'([A-Z]+)=([^,]+)', re.IGNORECASE)
_RE_SPN_BASE = re.compile(r'^([^/]+)/(.+)$', re.IGNORECASE)
_RE_GPCPATH = re.compile(
    r'^(\\\\)([A-Z0-9][A-Z0-9.\-]+)(\\.*?\\)([A-Z0-9][A-Z0-9.\-]+)(\\POLICIES\\.*)?$',
    re.IGNORECASE,
)
_RE_URL_HOST = re.compile(
    r'^(https?://)([^/]+)(/.*)$', re.IGNORECASE
)
_RE_EMBEDDED_FQDN = re.compile(
    # Match dotted names where the final label is a short TLD (2-6 alpha chars).
    # This excludes .NET class names like Registry.RemoteRegistryException
    # whose final labels are long words (Exception, Strategy, etc.).
    r'(?<![A-Z0-9\-])([A-Z0-9][A-Z0-9\-]*(?:\.[A-Z0-9][A-Z0-9\-]*)+\.[A-Z]{2,6})(?![A-Z0-9\-])',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Fields blanked unconditionally
# ---------------------------------------------------------------------------
# Free-text, PII, path, address, and secret fields. These carry org-specific
# data with no structural value for attack-path analysis and cannot be reliably
# pattern-masked (they routinely hide passwords, usernames, share paths, and
# personal data). Every field listed here is emptied on every object.
BLANK_FIELDS: frozenset = frozenset({
    # Free-text / descriptive
    "description", "displayname", "title", "info", "comment", "notes",
    # Personal names
    "givenname", "surname",
    # Org structure / contact
    "company", "department", "manager", "managedby",
    "physicaldeliveryofficename", "location", "co", "c", "l", "st",
    "streetaddress", "postofficebox",
    # Contact numbers
    "telephonenumber", "mobile", "ipphone", "pager",
    # Mail (note: 'email' is handled separately to preserve @domain structure)
    "mail",
    # Paths (UNC and local — contain usernames, share names, folder structure)
    "homedirectory", "logonscript", "profilepath", "scriptpath",
    "homedrive", "unixhomedirectory",
    # Secrets — must never reach an LLM
    "userpassword", "unixpassword", "unicodepassword", "sfupassword",
    "ms-mcs-admpwd", "msmcs-admpwd", "mcs-admpwd",
    # SharpHound-rendered text variants
    "useraccountcontrol_text",
})


# ---------------------------------------------------------------------------
# Core masking helpers
# ---------------------------------------------------------------------------

def _mask_domain(domain: str, store: MappingStore) -> str:
    """Mask a bare domain name like TRAINING.LOCAL."""
    domain_token, _ = store.register_domain_and_triple(
        domain, _domain_to_fake_triple(domain)
    )
    return domain_token


def _domain_to_fake_triple(domain: str) -> str:
    return f"__domain__{domain.upper()}__"


def _is_sid_like(value: str) -> bool:
    """
    Return True if a string is a SID or a domain-prefixed SID, e.g.:
        S-1-5-21-1-2-3-512
        S-1-5-32-544
        S-1-1-0
        TRAINING.LOCAL-S-1-5-32-544
    Used to detect names/identifiers that are actually SIDs so they get
    masked consistently with SID handling rather than as free-text names.
    """
    if not value:
        return False
    if value.upper().startswith("S-1-"):
        return True
    if re.search(r'-S-1-[0-9]', value, re.IGNORECASE):
        return True
    return False


def _mask_sid(sid: str, store: MappingStore) -> str:
    """
    Mask a SID string, preserving structure.
    """
    # Domain-prefixed SID: DOMAIN.LOCAL-<wellknown SID body>
    # e.g. TRAINING.LOCAL-S-1-1-0, TRAINING.LOCAL-S-1-5-11, TRAINING.LOCAL-S-1-5-32-544
    m = _RE_DOMAIN_PREFIXED_SID.match(sid)
    if m:
        domain_part = m.group(1)
        sid_body    = m.group(2)   # full "S-1-..." preserved verbatim
        masked_domain = _mask_domain(domain_part, store)
        return f"{masked_domain}-{sid_body}"

    # Standard domain SID: S-1-5-21-A-B-C[-RID...]
    m = _RE_DOMAIN_SID.match(sid)
    if m:
        prefix   = m.group(1)
        triple   = m.group(2)
        trailing = m.group(3)
        _, triple_token = store.register_domain_and_triple(
            f"__triple__{triple.upper()}__", triple
        )
        return f"{prefix}{triple_token}{trailing}"

    return sid


def _mask_name_at_domain(name: str, store: MappingStore, name_type: str,
                          type_name: str) -> str:
    """Mask a NAME@DOMAIN string."""
    m = _RE_AT_DOMAIN.match(name)
    if not m:
        return store.register(_type_to_bucket(name_type), name, type_name)
    bare, domain = m.group(1), m.group(2)
    masked_domain = _mask_domain(domain, store)

    if name_type in ("group", "container") and (
        is_default_group(bare) or bare.upper() in TIER_ZERO_NAMED_ASSETS
    ):
        return f"{bare}@{masked_domain}"

    bucket = _type_to_bucket(name_type)
    masked_bare = store.register(bucket, bare, type_name)
    return f"{masked_bare}@{masked_domain}"


def _type_to_bucket(name_type: str) -> str:
    return {
        "user":         "users",
        "computer":     "computers",
        "group":        "groups",
        "gpo":          "gpos",
        "ou":           "ous",
        "domain":       "domains",
        "container":    "containers",
        "ca":           "cas",
        "certtemplate": "certtemplates",
    }.get(name_type, "users")


def _mask_dn(dn: str, store: MappingStore, obj_type: str) -> str:
    """Mask a Distinguished Name component by component."""
    if not dn:
        return dn
    parts = _RE_DN_COMPONENT.findall(dn)
    if not parts:
        return dn

    dc_parts = [v for k, v in parts if k.upper() == "DC"]
    if dc_parts:
        original_domain = ".".join(dc_parts)
        masked_domain = _mask_domain(original_domain, store)
        masked_dc_parts = masked_domain.split(".")
    else:
        masked_dc_parts = []

    result_parts = []
    dc_idx = 0

    for attr, value in parts:
        attr_up = attr.upper()
        if attr_up == "DC":
            if dc_idx < len(masked_dc_parts):
                result_parts.append(f"DC={masked_dc_parts[dc_idx]}")
                dc_idx += 1
            else:
                result_parts.append(f"DC={value}")
        elif attr_up == "CN":
            result_parts.append(f"CN={_mask_cn_value(value, obj_type, store)}")
        elif attr_up == "OU":
            if value.upper() in DEFAULT_GROUP_NAMES:
                result_parts.append(f"OU={value}")
            else:
                result_parts.append(f"OU={store.register('ous', value, TYPE_OU)}")
        else:
            result_parts.append(f"{attr}={value}")

    return ",".join(result_parts)


def _mask_cn_value(value: str, obj_type: str, store: MappingStore) -> str:
    """Mask a CN= value based on object type context."""
    _SYSTEM_CNS = {
        "COMPUTERS", "USERS", "SYSTEM", "BUILTIN", "INFRASTRUCTURE",
        "LOSTANDFOUND", "FOREIGNSECURITYPRINCIPALS", "NTDS QUOTAS",
        "PROGRAM DATA", "MANAGED SERVICE ACCOUNTS",
        "MICROSOFT EXCHANGE SECURITY GROUPS", "KEYS", "WINSOCKSERVICES",
        "RPCSERVICES", "TPMSYSTEMS", "AIA", "ENROLLMENT SERVICES",
        "PUBLIC KEY SERVICES", "SERVICES", "CERTIFICATE TEMPLATES",
        "CERTIFICATION AUTHORITIES", "KRA", "OID", "CONFIGURATION",
        "SCHEMA", "POLICIES", "NTL", "PKI HEALTH",
        "ADMINSDHOLDER",   # default Tier Zero object, identified by its DN
    }
    if re.match(r'^\{[0-9A-F-]{36}\}$', value, re.IGNORECASE):
        return value
    if value.upper() in _SYSTEM_CNS or value.upper() in TIER_ZERO_NAMED_ASSETS:
        return value
    type_map = {
        "users":         ("users",         TYPE_USER),
        "computers":     ("computers",     TYPE_COMPUTER),
        "groups":        ("groups",        TYPE_GROUP),
        "gpos":          ("gpos",          TYPE_GPO),
        "ous":           ("ous",           TYPE_OU),
        "domains":       ("domains",       TYPE_DOMAIN),
        "cas":           ("cas",           TYPE_CA),
        "aiacas":        ("cas",           TYPE_CA),
        "enterprisecas": ("cas",           TYPE_CA),
        "certtemplates": ("certtemplates", TYPE_CERTTEMPLATE),
        "containers":    ("containers",    TYPE_CONTAINER),
    }
    bucket, ttype = type_map.get(obj_type, ("containers", TYPE_CONTAINER))
    return store.register(bucket, value, ttype)


def _mask_fqdn(fqdn: str, store: MappingStore, host_type: str = "computer") -> str:
    """Mask HOSTNAME.DOMAIN.TLD."""
    m = _RE_FQDN.match(fqdn)
    if not m:
        return fqdn
    host, domain = m.group(1), m.group(2)
    bucket_map = {
        "computer": ("computers", TYPE_COMPUTER),
        "ca":       ("cas",       TYPE_CA),
    }
    bucket, ttype = bucket_map.get(host_type, ("computers", TYPE_COMPUTER))
    masked_host   = store.register(bucket, host, ttype)
    masked_domain = _mask_domain(domain, store)
    return f"{masked_host}.{masked_domain}"


def _mask_spn(spn: str, store: MappingStore) -> str:
    """
    Mask a Service Principal Name in any format.
    Service label is preserved; host and domain parts are masked.
    """
    _WELLKNOWN = {"kadmin/changepw", "host/localhost"}
    if spn.lower() in _WELLKNOWN:
        return spn

    m = _RE_SPN_BASE.match(spn)
    if not m:
        return spn

    service_label = m.group(1)
    host_part     = m.group(2)

    # Split on "/" for multi-segment SPNs (e.g. ldap/host/domain or HOST/host/NETBIOS)
    sub_segments = host_part.split("/")
    masked_segments = []

    for i, seg in enumerate(sub_segments):
        # Handle :port or :instance suffix
        if ":" in seg:
            host_bit, colon_suffix = seg.split(":", 1)
            masked_host = _mask_spn_token(host_bit, store, i)
            masked_segments.append(f"{masked_host}:{colon_suffix}")
        else:
            masked_segments.append(_mask_spn_token(seg, store, i))

    return f"{service_label}/{'/'.join(masked_segments)}"


def _mask_spn_token(token: str, store: MappingStore, position: int) -> str:
    """Mask a single token within an SPN (host name, realm, NetBIOS domain)."""
    if not token:
        return token
    # 3-part FQDN (host.domain.tld)
    if _RE_FQDN.match(token):
        return _mask_fqdn(token, store, "computer")
    # UUID._subdomain.domain.local pattern
    # e.g. a8373867-56d0-486b-88b5-5848fcb5fcfb._msdcs.training.local
    dot_parts = token.split(".", 1)
    if len(dot_parts) == 2 and re.match(r"^[0-9A-F]{8}-", dot_parts[0], re.IGNORECASE):
        # Strip leading underscore-prefixed service labels (like _msdcs)
        # and mask the real domain part that follows
        remainder = dot_parts[1]
        service_prefix = ""
        if remainder.startswith("_"):
            sub = remainder.split(".", 1)
            if len(sub) == 2:
                service_prefix = sub[0] + "."
                remainder = sub[1]
        masked_domain = _mask_domain(remainder, store) if "." in remainder else remainder
        return f"{dot_parts[0]}.{service_prefix}{masked_domain}"
    # UUID alone (no dots) — preserve, not org-specific
    if re.match(r"^[0-9A-F]{8}-[0-9A-F]{4}-", token, re.IGNORECASE):
        return token
    # 2-part domain name used as realm suffix (e.g. "training.local")
    # Appears in SPNs like: GC/host.domain/training.local
    if len(dot_parts) == 2 and "." not in dot_parts[1]:
        if re.match(r"^[A-Z0-9][A-Z0-9-]*$", dot_parts[0], re.IGNORECASE) and            re.match(r"^[A-Z]{2,}$", dot_parts[1], re.IGNORECASE):
            return _mask_domain(token, store)
    # Plain alpha/digit/hyphen token (no dots)
    if re.match(r"^[A-Z0-9][A-Z0-9-]*$", token, re.IGNORECASE):
        if position == 0:
            return store.register("computers", token, TYPE_COMPUTER)
        else:
            # Could be NetBIOS domain label or short hostname
            return store.register("domains", token, TYPE_DOMAIN)
    return token


def _mask_gpcpath(path: str, store: MappingStore) -> str:
    r"""Mask domain names in a GPO gpcpath UNC path."""
    if not path:
        return path
    m = _RE_GPCPATH.match(path)
    if m:
        slash   = m.group(1)
        domain1 = m.group(2)
        mid     = m.group(3)
        domain2 = m.group(4)
        tail    = m.group(5) or ""
        return f"{slash}{_mask_domain(domain1, store)}{mid}{_mask_domain(domain2, store)}{tail}"
    return path


def _mask_url(url: str, store: MappingStore) -> str:
    """
    Mask hostname and any org-specific content in a URL.
    Three-pass approach on the path portion:
      1. Scrub embedded FQDNs (e.g. domain names in redirect paths)
      2. Replace any registered org names appearing literally in the path
         e.g. /training-ADCS-CA-1_CES_Kerberos/ -> /<masked-ca-token>_CES_Kerberos/
    """
    m = _RE_URL_HOST.match(url)
    if not m:
        return url
    scheme = m.group(1)
    host   = m.group(2)
    rest   = m.group(3)

    if "." in host:
        masked_host = _mask_fqdn(host, store, "ca")
    else:
        masked_host = store.register("computers", host, TYPE_COMPUTER)

    masked_rest = _scrub_fqdns_in_text(rest, store)
    masked_rest = _scrub_known_tokens_in_text(masked_rest, store)
    return f"{scheme}{masked_host}{masked_rest}"


def _scrub_known_tokens_in_text(text: str, store: MappingStore) -> str:
    """
    Replace any registered org-specific names that appear literally in free text.
    Catches CA names, caname labels, or similar strings embedded in URL path segments
    or error messages that are not FQDNs and would be missed by _scrub_fqdns_in_text.
    Operates on the "cas" bucket (the most common source of such leaks).
    """
    if not text:
        return text
    result = text
    for original, token in store.iter_bucket("cas"):
        if original.lower() in result.lower():
            result = re.sub(re.escape(original), token, result, flags=re.IGNORECASE)
    return result


def _scrub_fqdns_in_text(text: str, store: MappingStore) -> str:
    """
    Replace any FQDN (host.domain.tld or domain.tld) found in free-text
    with masked tokens. Used for error strings, URL paths, description fields.
    """
    if not text:
        return text

    def replace_fqdn(match: re.Match) -> str:
        candidate = match.group(1)
        fqdn_m = _RE_FQDN.match(candidate)
        if fqdn_m:
            return _mask_fqdn(candidate, store, "computer")
        if "." in candidate:
            return _mask_domain(candidate, store)
        return candidate

    return _RE_EMBEDDED_FQDN.sub(replace_fqdn, text)


# ---------------------------------------------------------------------------
# Per-object-type masking dispatch
# ---------------------------------------------------------------------------

def _link_domain_from_props(props: dict, obj: dict, obj_type: str,
                             store: MappingStore) -> None:
    """
    If this object exposes both a domain NAME and the domain SID triple, link
    them authoritatively so they share one token. Sources, in priority order:
      - domain object: Properties.name (FQDN) + ObjectIdentifier/domainsid
      - any object:    Properties.domain (FQDN) + Properties.domainsid
    """
    def triple_of(sid: str):
        if not sid:
            return None
        m = _RE_DOMAIN_SID.match(sid)
        return m.group(2) if m else None

    # Domain object: its own name is the FQDN, OID/domainsid is the SID
    if obj_type == "domains":
        name = props.get("name")
        sid  = obj.get("ObjectIdentifier") or props.get("domainsid")
        triple = triple_of(sid)
        if name and triple and not _is_sid_like(name):
            store.link_domain_triple(name, triple)
            return

    # Any object with domain + domainsid
    name = props.get("domain")
    triple = triple_of(props.get("domainsid"))
    if name and triple:
        store.link_domain_triple(name, triple)


def mask_object(obj: dict, obj_type: str, store: MappingStore) -> dict:
    """
    Return a deep copy of *obj* with all org-specific fields masked.
    *obj_type* is the value of meta.type (e.g. "users", "computers", ...).
    """
    o = copy.deepcopy(obj)
    props = o.get("Properties", {})

    # ---- Link domain name <-> domain SID triple UPFRONT --------------------
    # Whenever an object carries both its domain name and the domain SID, link
    # them so they resolve to ONE domain token. Doing this first prevents the
    # one-sided placeholder entries (__DOMAIN__ / __TRIPLE__) that otherwise
    # leave unresolvable anomalies in mapping.json.
    _link_domain_from_props(props, o, obj_type, store)

    # ---- Common Properties fields ----------------------------------------
    if "domain" in props:
        props["domain"] = _mask_domain(props["domain"], store)

    if "domainsid" in props and props["domainsid"]:
        props["domainsid"] = _mask_sid(props["domainsid"], store)

    if "name" in props and props["name"]:
        name_val = props["name"]
        # A name can itself be an unresolved SID (e.g. SharpHound couldn't
        # resolve a builtin's friendly name → "DOMAIN.LOCAL-S-1-5-32-544").
        # Mask it the SAME way as a SID so it stays consistent with the OID,
        # rather than turning it into a generic group/user token.
        if _is_sid_like(name_val):
            props["name"] = _mask_sid(name_val, store)
        elif obj_type == "computers" and _RE_FQDN.match(name_val):
            # Computer names are HOSTNAME.DOMAIN.LOCAL (not @DOMAIN format)
            props["name"] = _mask_fqdn(name_val, store, "computer")
        elif obj_type == "domains":
            # Domain object's own name IS the domain FQDN itself
            props["name"] = _mask_domain(name_val, store)
        else:
            props["name"] = _mask_name_at_domain(
                name_val, store,
                _obj_type_to_name_type(obj_type), _obj_type_to_token_type(obj_type)
            )

    if "distinguishedname" in props and props["distinguishedname"]:
        props["distinguishedname"] = _mask_dn(
            props["distinguishedname"], store, obj_type
        )

    if "samaccountname" in props and props["samaccountname"]:
        sam = props["samaccountname"]
        dollar_suffix = sam.endswith("$")
        bare = sam.rstrip("$")
        if is_default_group(bare) or bare.upper() in TIER_ZERO_NAMED_ASSETS:
            # Preserved asset (e.g. DnsAdmins): keep samaccountname intact so
            # BloodHound's name/samaccountname-based identification still works,
            # and so we don't register a preserved name into the users bucket.
            masked = bare
        elif obj_type == "computers":
            masked = store.register("computers", bare, TYPE_COMPUTER)
        else:
            masked = store.register("users", bare, TYPE_USER)
        props["samaccountname"] = f"{masked}$" if dollar_suffix else masked

    # ---- Free-text / PII / path / secret fields: BLANK unconditionally ------
    # These carry org-specific data (names, paths, phone numbers, passwords,
    # addresses) with no structural value for attack-path analysis, and cannot
    # be reliably pattern-masked. Blanking is the only safe option. See
    # BLANK_FIELDS for the complete list.
    for field in BLANK_FIELDS:
        if field in props and props[field]:
            props[field] = "" if isinstance(props[field], str) else props[field]

    if "email" in props and props["email"]:
        props["email"] = _mask_email(props["email"], store)

    if "serviceprincipalnames" in props and props["serviceprincipalnames"]:
        props["serviceprincipalnames"] = [
            _mask_spn(s, store) for s in props["serviceprincipalnames"]
        ]

    if "sidhistory" in props and props["sidhistory"]:
        props["sidhistory"] = [_mask_sid(s, store) for s in props["sidhistory"]]

    if "allowedtodelegate" in props and props["allowedtodelegate"]:
        props["allowedtodelegate"] = [
            _mask_spn(h, store) if "/" in h
            else (_mask_fqdn(h, store, "computer") if "." in h
                  else store.register("computers", h, TYPE_COMPUTER))
            for h in props["allowedtodelegate"]
        ]

    # ---- Type-specific Properties ----------------------------------------
    if obj_type == "gpos":
        if "gpcpath" in props and props["gpcpath"]:
            props["gpcpath"] = _mask_gpcpath(props["gpcpath"], store)

    if obj_type in ("enterprisecas", "aiacas"):
        if "caname" in props and props["caname"]:
            props["caname"] = store.register("cas", props["caname"], TYPE_CA)
        if "dnshostname" in props and props["dnshostname"]:
            props["dnshostname"] = _mask_fqdn(props["dnshostname"], store, "ca")

    # ---- Top-level SID / relationship fields -----------------------------
    _mask_toplevel_sids(o, store)
    _mask_aces(o.get("Aces", []), store)
    _mask_members(o.get("Members", []), store)
    _mask_members(o.get("AllowedToDelegate", []), store)
    _mask_members(o.get("AllowedToAct", []), store)
    _mask_members(o.get("HasSIDHistory", []), store)

    for sid_field in ("PrimaryGroupSID", "DomainSID", "HostingComputer", "ForestRootIdentifier"):
        if o.get(sid_field):
            o[sid_field] = _mask_sid(o[sid_field], store)

    if "ObjectIdentifier" in o and o["ObjectIdentifier"]:
        oid = o["ObjectIdentifier"]
        # Handle S-1-..., DOMAIN.LOCAL-S-1-5-..., DOMAIN.LOCAL-S-1-1-0 etc.
        if oid.upper().startswith("S-") or re.search(r'-S-1-[0-9]+-', oid, re.IGNORECASE):
            o["ObjectIdentifier"] = _mask_sid(oid, store)
        # GUIDs are not org-specific - preserve

    _mask_contained_by(o.get("ContainedBy"), store)
    _mask_child_objects(o.get("ChildObjects", []), store)
    _mask_trusts(o.get("Trusts", []), store)
    _mask_gpo_changes(o.get("GPOChanges"), store)
    _mask_local_groups(o.get("LocalGroups", []), store)

    for sess_key in ("Sessions", "PrivilegedSessions", "RegistrySessions"):
        _mask_sessions(o.get(sess_key), store)

    _mask_user_rights(o.get("UserRights", []), store)
    _mask_spn_targets(o.get("SPNTargets", []), store)
    _mask_smb_info(o.get("SmbInfo"), store)
    _mask_registry_data(o.get("DCRegistryData"), store)
    _mask_registry_data(o.get("NTLMRegistryData"), store)
    _mask_status(o.get("Status"), store)
    _mask_ca_registry(o.get("CARegistryData"), store)
    _mask_http_endpoints(o.get("HttpEnrollmentEndpoints", []), store)

    o["Properties"] = props
    return o


# ---------------------------------------------------------------------------
# Field-level helpers
# ---------------------------------------------------------------------------

def _mask_toplevel_sids(o: dict, store: MappingStore) -> None:
    for key in ("DumpSMSAPassword",):
        if o.get(key):
            o[key] = [_mask_sid(s, store) if isinstance(s, str) else s for s in o[key]]


def _mask_aces(aces: list, store: MappingStore) -> None:
    for ace in aces:
        if ace.get("PrincipalSID"):
            ace["PrincipalSID"] = _mask_sid(ace["PrincipalSID"], store)


def _mask_members(members: list, store: MappingStore) -> None:
    for m in members:
        if isinstance(m, dict) and m.get("ObjectIdentifier"):
            oid = m["ObjectIdentifier"]
            # Match both S-1-5-... and DOMAIN.LOCAL-S-1-5-... patterns
            if oid.upper().startswith("S-") or re.search(r"-S-1-[0-9]+-", oid, re.IGNORECASE):
                m["ObjectIdentifier"] = _mask_sid(oid, store)


def _mask_contained_by(cb: Optional[dict], store: MappingStore) -> None:
    if not cb:
        return
    if cb.get("ObjectIdentifier", "").upper().startswith("S-"):
        cb["ObjectIdentifier"] = _mask_sid(cb["ObjectIdentifier"], store)


def _mask_child_objects(children: list, store: MappingStore) -> None:
    for c in children:
        if isinstance(c, dict) and c.get("ObjectIdentifier", "").upper().startswith("S-"):
            c["ObjectIdentifier"] = _mask_sid(c["ObjectIdentifier"], store)


def _mask_trusts(trusts: list, store: MappingStore) -> None:
    for t in trusts:
        name = t.get("TargetDomainName")
        sid  = t.get("TargetDomainSid")

        # Link the trusted domain's name and SID triple so they share ONE token.
        # link_domain_triple also cleans up any placeholder entries a one-sided
        # earlier call may have created, preventing unresolvable anomalies.
        if name and sid:
            m = _RE_DOMAIN_SID.match(sid)
            if m:
                store.link_domain_triple(name, m.group(2))

        if sid:
            t["TargetDomainSid"] = _mask_sid(sid, store)
        if name:
            t["TargetDomainName"] = _mask_domain(name, store)


def _mask_gpo_changes(gpc: Optional[dict], store: MappingStore) -> None:
    if not gpc:
        return
    for key in ("LocalAdmins", "RemoteDesktopUsers", "DcomUsers", "PSRemoteUsers"):
        for entry in gpc.get(key, []):
            _mask_members(entry.get("Results", []), store)
    _mask_members(gpc.get("AffectedComputers", []), store)


def _mask_local_groups(lgs: list, store: MappingStore) -> None:
    for lg in lgs:
        if lg.get("ObjectIdentifier"):
            sid = lg["ObjectIdentifier"]
            if sid.upper().startswith("S-") or re.match(r'^[A-Z].*\.LOCAL-', sid, re.I):
                lg["ObjectIdentifier"] = _mask_sid(sid, store)
        _mask_members(lg.get("Results", []), store)


def _mask_sessions(sess: Optional[dict], store: MappingStore) -> None:
    if not sess:
        return
    for r in sess.get("Results", []):
        if r.get("ComputerSID"):
            r["ComputerSID"] = _mask_sid(r["ComputerSID"], store)
        if r.get("UserSID"):
            r["UserSID"] = _mask_sid(r["UserSID"], store)
    if sess.get("FailureReason") and isinstance(sess["FailureReason"], str):
        sess["FailureReason"] = _scrub_fqdns_in_text(sess["FailureReason"], store)


def _mask_user_rights(rights: list, store: MappingStore) -> None:
    for right in rights:
        _mask_members(right.get("Results", []), store)
        if right.get("FailureReason") and isinstance(right["FailureReason"], str):
            right["FailureReason"] = _scrub_fqdns_in_text(right["FailureReason"], store)


def _mask_spn_targets(targets: list, store: MappingStore) -> None:
    """SPNTargets contain ComputerSID (a full domain SID) and Port/Service."""
    for t in targets:
        if t.get("ComputerSID"):
            t["ComputerSID"] = _mask_sid(t["ComputerSID"], store)


def _mask_smb_info(smb: Optional[dict], store: MappingStore) -> None:
    """SmbInfo.Result.DnsComputerName contains an FQDN."""
    if not smb:
        return
    result = smb.get("Result")
    if result and isinstance(result, dict):
        if result.get("DnsComputerName"):
            dn = result["DnsComputerName"]
            if "." in dn:
                result["DnsComputerName"] = _mask_fqdn(dn, store, "computer")
            else:
                result["DnsComputerName"] = store.register("computers", dn, TYPE_COMPUTER)
    if smb.get("FailureReason") and isinstance(smb["FailureReason"], str):
        smb["FailureReason"] = _scrub_fqdns_in_text(smb["FailureReason"], store)


def _mask_registry_data(reg: Optional[dict], store: MappingStore) -> None:
    """
    DCRegistryData and NTLMRegistryData may have FailureReason strings with hostnames.
    NTLMRegistryData has FailureReason at the top level.
    DCRegistryData has sub-keys each as dicts with their own FailureReason.
    """
    if not reg or not isinstance(reg, dict):
        return
    # Top-level FailureReason (NTLMRegistryData pattern)
    if reg.get("FailureReason") and isinstance(reg["FailureReason"], str):
        reg["FailureReason"] = _scrub_fqdns_in_text(reg["FailureReason"], store)
    # Nested sub-key FailureReason (DCRegistryData pattern)
    for key, val in reg.items():
        if isinstance(val, dict):
            if val.get("FailureReason") and isinstance(val["FailureReason"], str):
                val["FailureReason"] = _scrub_fqdns_in_text(val["FailureReason"], store)


def _mask_status(status: Optional[dict], store: MappingStore) -> None:
    """Status.Error may contain hostnames in SharpHound error messages."""
    if not status or not isinstance(status, dict):
        return
    if status.get("Error") and isinstance(status["Error"], str):
        status["Error"] = _scrub_fqdns_in_text(status["Error"], store)


def _mask_ca_registry(ca_reg: Optional[dict], store: MappingStore) -> None:
    if not ca_reg:
        return
    ca_sec = ca_reg.get("CASecurity", {})
    if ca_sec:
        _mask_aces(ca_sec.get("Result", []), store)
    ea_rest = ca_reg.get("EnrollmentAgentRestrictions", {})
    if ea_rest:
        for entry in ea_rest.get("Result", []):
            if entry.get("AgentSID"):
                entry["AgentSID"] = _mask_sid(entry["AgentSID"], store)
            _mask_members(entry.get("Targets", []), store)


def _mask_http_endpoints(endpoints: list, store: MappingStore) -> None:
    for ep in endpoints:
        result = ep.get("Result", {})
        if result.get("Url"):
            result["Url"] = _mask_url(result["Url"], store)
        if ep.get("FailureReason") and isinstance(ep["FailureReason"], str):
            ep["FailureReason"] = _scrub_fqdns_in_text(ep["FailureReason"], store)


def _mask_email(email: str, store: MappingStore) -> str:
    if not email or "@" not in email:
        return email
    local, domain = email.rsplit("@", 1)
    return f"{store.register('users', local, TYPE_USER)}@{_mask_domain(domain, store)}"


# ---------------------------------------------------------------------------
# Type-name helpers
# ---------------------------------------------------------------------------

def _obj_type_to_name_type(obj_type: str) -> str:
    return {
        "users":         "user",
        "computers":     "computer",
        "groups":        "group",
        "gpos":          "gpo",
        "ous":           "ou",
        "domains":       "domain",
        "containers":    "container",
        "enterprisecas": "ca",
        "aiacas":        "ca",
        "certtemplates": "certtemplate",
    }.get(obj_type, "container")


def _obj_type_to_token_type(obj_type: str) -> str:
    return {
        "users":         TYPE_USER,
        "computers":     TYPE_COMPUTER,
        "groups":        TYPE_GROUP,
        "gpos":          TYPE_GPO,
        "ous":           TYPE_OU,
        "domains":       TYPE_DOMAIN,
        "containers":    TYPE_CONTAINER,
        "enterprisecas": TYPE_CA,
        "aiacas":        TYPE_CA,
        "certtemplates": TYPE_CERTTEMPLATE,
    }.get(obj_type, TYPE_CONTAINER)


if __name__ == "__main__":
    import sys
    print(
        "masker.py is a library module — not the CLI entrypoint.\n"
        "Run the tool with:\n\n"
        "  python3 houndmasker.py --new  file1.json file2.json ...\n"
        "  python3 houndmasker.py --extend file1.json file2.json ...\n\n"
        "All files (houndmasker.py, masker.py, mapping.py, safelist.py,\n"
        "token_gen.py) must be in the same directory.",
        file=sys.stderr
    )
    sys.exit(1)
