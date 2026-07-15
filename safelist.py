"""
safelist.py
-----------
Well-known AD group names and SID suffixes that BloodHound's built-in
Cypher queries depend on.  Nothing in this list is ever masked.
"""

# Case-insensitive exact match against the NAME PART (before the @DOMAIN suffix).
# All entries are stored uppercase for comparison.
DEFAULT_GROUP_NAMES: frozenset[str] = frozenset({
    # Standard domain groups
    "DOMAIN USERS",
    "DOMAIN ADMINS",
    "DOMAIN COMPUTERS",
    "DOMAIN CONTROLLERS",
    "DOMAIN GUESTS",
    "ENTERPRISE ADMINS",
    "ENTERPRISE READ-ONLY DOMAIN CONTROLLERS",
    "ENTERPRISE KEY ADMINS",
    "SCHEMA ADMINS",
    "GROUP POLICY CREATOR OWNERS",
    "PROTECTED USERS",
    "READ-ONLY DOMAIN CONTROLLERS",
    "CLONEABLE DOMAIN CONTROLLERS",
    "KEY ADMINS",
    # Built-in local groups (BUILTIN\...)
    "ADMINISTRATORS",
    "USERS",
    "GUESTS",
    "ACCOUNT OPERATORS",
    "BACKUP OPERATORS",
    "PRINT OPERATORS",
    "SERVER OPERATORS",
    "REMOTE DESKTOP USERS",
    "REMOTE MANAGEMENT USERS",
    "NETWORK CONFIGURATION OPERATORS",
    "CRYPTOGRAPHIC OPERATORS",
    "DISTRIBUTED COM USERS",
    "PERFORMANCE MONITOR USERS",
    "PERFORMANCE LOG USERS",
    "EVENT LOG READERS",
    "CERTIFICATE SERVICE DCOM ACCESS",
    "CERTSVC_DCOM_ACCESS",
    "INCOMING FOREST TRUST BUILDERS",
    "WINDOWS AUTHORIZATION ACCESS GROUP",
    "TERMINAL SERVER LICENSE SERVERS",
    "PRE-WINDOWS 2000 COMPATIBLE ACCESS",
    "DENIED RODC PASSWORD REPLICATION GROUP",
    "ALLOWED RODC PASSWORD REPLICATION GROUP",
    "RAS AND IAS SERVERS",
    "HYPER-V ADMINISTRATORS",
    "ACCESS CONTROL ASSISTANCE OPERATORS",
    "STORAGE REPLICA ADMINISTRATORS",
    # Well-known pseudo-groups / identities
    "EVERYONE",
    "AUTHENTICATED USERS",
    "NETWORK SERVICE",
    "LOCAL SERVICE",
    "SYSTEM",
    "INTERACTIVE",
    "NETWORK",
    "SERVICE",
    "CREATOR OWNER",
    "CREATOR GROUP",
    "DIALUP",
    "BATCH",
    "ANONYMOUS LOGON",
    "ENTERPRISE DOMAIN CONTROLLERS",
    "IUSR",
    # Built-in container names (containers.json names that are AD defaults)
    "ADMINSDHOLDER",   # default Tier Zero object; BloodHound identifies it by name/DN
    "FOREIGNSECURITYPRINCIPALS",
    "BUILTIN",
    "COMPUTERS",
    "USERS",
    "MANAGED SERVICE ACCOUNTS",
    "PROGRAM DATA",
    "SYSTEM",
    "INFRASTRUCTURE",
    "LOSTANDFOUND",
    "NTDS QUOTAS",
    "TPMSYSTEMS",
    "KEYS",
    "WINSOCKSERVICES",
    "RPCSERVICES",
    "DOMAINDNSZONESCONTAINER",
    "FORESTDNSZONESCONTAINER",
    # Certificate-related well-known containers
    "AIA",
    "CERTIFICATION AUTHORITIES",
    "CERTIFICATE TEMPLATES",
    "ENROLLMENT SERVICES",
    "NTL",
    "PKI HEALTH",
    "PUBLIC KEY SERVICES",
    "KRA",
    "OID",
    "CERTIFICATE",
    # GPOs that are Microsoft defaults
    "DEFAULT DOMAIN POLICY",
    "DEFAULT DOMAIN CONTROLLERS POLICY",
})


# ---------------------------------------------------------------------------
# Tier Zero assets that BloodHound identifies by NAME/DN rather than by a
# well-known SID. Source: SpecterOps TierZeroTable
# (https://github.com/SpecterOps/TierZeroTable) — the "Identification" column.
#
# Inclusion criterion (why a name lives here):
#   1. The asset is Tier Zero, AND
#   2. BloodHound identifies it by a NAME / CN / DN, not a well-known SID
#      (SID-identified assets survive masking already via preserved RIDs and
#      SID bodies), AND
#   3. That name is a Microsoft/product DEFAULT — identical in every AD forest
#      — so preserving it leaks nothing organization-specific.
#
# These are the names masking would otherwise tokenise, which silently strips
# the asset's Tier Zero identity on re-import (e.g. DnsAdmins has no fixed RID,
# so it can ONLY be recognised by its name). Preserving them is the same
# rationale as DEFAULT_GROUP_NAMES: universal defaults are not secrets.
#
# NOTE: preserving the name keeps the asset identifiable and keeps BloodHound's
# name-based analysis working. For assets NOT in BloodHound's automatic default
# Tier Zero set (DnsAdmins, Exchange groups, DHCP Administrators — all "Phase
# Two" / manual per the table), this does NOT by itself re-tag them Tier Zero
# on import; that still requires manual tagging / the re-tag script. What it
# guarantees is that the object can be found by its real name to be tagged.
TIER_ZERO_NAMED_ASSETS: frozenset[str] = frozenset({
    "DNSADMINS",                    # DLL load on the DC → effectively Tier Zero
    "EXCHANGE TRUSTED SUBSYSTEM",   # WriteDACL over the domain (pre-2019 CU)
    "EXCHANGE WINDOWS PERMISSIONS", # WriteDACL over the domain (pre-2019 CU)
    "NTAUTHCERTIFICATES",           # NTAuth store (CN=NTAuthCertificates) — cert-based DA
    "DHCP ADMINISTRATORS",          # config-dependent (DNS record takeover) — universal name
})

# Well-known SID suffixes (the final RID). BloodHound Cypher queries
# rely on these being recognisable.  The domain-triple portion is still
# masked; only the RID is preserved (as agreed).
WELL_KNOWN_RIDS: frozenset[str] = frozenset({
    "500", "501", "502",            # Administrator, Guest, KRBTGT
    "512", "513", "514", "515",     # Domain Admins, Users, Guests, Computers
    "516", "517", "518", "519",     # DCs, Cert Publishers, Schema Admins, Ent Admins
    "520", "521", "522", "525",     # GPO Creators, RODC, Clonable DCs, Protected Users
    "526", "527",                   # Key Admins, Ent Key Admins
})

# SID prefixes that are purely well-known and never org-specific.
# These appear in DOMAIN.LOCAL-S-1-5-XX style entries in the ACEs.
BUILTIN_SID_SUFFIXES: frozenset[str] = frozenset({
    # S-1-5-32-XXX  (BUILTIN hive)
    "32-544", "32-545", "32-546", "32-547", "32-548", "32-549",
    "32-550", "32-551", "32-552", "32-553", "32-554", "32-555",
    "32-556", "32-557", "32-558", "32-559", "32-560", "32-561",
    "32-562", "32-568", "32-569", "32-573", "32-574", "32-575",
    "32-576", "32-577", "32-578", "32-579", "32-580",
    # S-1-5-X  (well-known authority SIDs)
    "1-5-9",    # Enterprise Domain Controllers
    "1-5-11",   # Authenticated Users
    "1-5-17",   # IUSR
})



def is_default_group(name: str) -> bool:
    """
    Return True if *name* (which may include an @DOMAIN suffix) refers to
    a well-known default AD group that must not be masked.
    Comparison is case-insensitive.
    """
    bare = name.upper().split("@")[0].strip()
    return bare in DEFAULT_GROUP_NAMES


def is_builtin_domain_prefixed_sid(sid: str) -> bool:
    """
    Return True for DOMAIN.LOCAL-S-1-5-XX style SIDs where the S-1-5-XX
    portion is a well-known builtin SID (i.e. the DOMAIN prefix is just a
    namespace tag that BloodHound adds, not an org-specific domain triple).

    Examples that return True:
        TRAINING.LOCAL-S-1-5-32-544
        TRAINING.LOCAL-S-1-5-11
        TRAINING.LOCAL-S-1-5-9
    """
    # Pattern: <DOMAIN>-S-1-5-<suffix>
    import re
    m = re.match(r'^[^-].*?-S-1-5-(.+)$', sid)
    if not m:
        return False
    suffix = m.group(1)
    # Check against known builtin suffixes
    for known in BUILTIN_SID_SUFFIXES:
        if suffix == known or suffix.startswith(known.split("-")[0] + "-"):
            if suffix == known:
                return True
    return suffix in {s.lstrip("1-5-") for s in BUILTIN_SID_SUFFIXES} or \
           any(sid.endswith(f"S-1-5-{s}") for s in BUILTIN_SID_SUFFIXES)


if __name__ == "__main__":
    import sys
    print(
        f"This is a library module. Run the tool with:\n\n"
        "  python3 houndmasker.py --new  file1.json file2.json ...\n"
        "  python3 houndmasker.py --extend file1.json file2.json ...",
        file=sys.stderr
    )
    sys.exit(1)
