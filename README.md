# HoundMasker

**Privacy-preserving attack-path analysis for BloodHound.**

Mask organization-specific data in BloodHound Community Edition JSON exports so
the graph can be safely shared with an LLM or AI for attack-path analysis,
without leaking domain names, usernames, hostnames, or any other sensitive
identifiers.

The tool strips identifying **labels** while preserving the full graph
**structure**. An AI analyzing the masked data reaches the same security
conclusions ("user47 has a 3-hop path to Domain Admins") without ever seeing
who user47 really is.

<!-- ADD YOUR BLOG POST URL BELOW -->
> **Full write-up and walkthrough:** _add your blog post link here_ (`https://blog.abhis3k.in/...`)
>
> The post covers the problem, the design decisions, and a start-to-finish
> walkthrough: mask, import into BloodHound, analyze with AI over MCP, then unmask.

---

## What it does

- Replaces domain names, usernames, computer names, custom group names, GPO
  names, OU names, CA names, SPNs, and distinguished names with opaque tokens.
- Replaces the domain portion of every Windows SID with a random numeric triple,
  keeping the SID syntactically valid so BloodHound CE re-imports the data
  cleanly and all graph edges (group membership, ACLs, sessions) stay intact.
- Blanks free-text, PII, and secret fields entirely (passwords, paths, names).
- Preserves everything BloodHound's analysis depends on: default AD group names,
  well-known SID suffixes, object kinds, and the **Tier Zero assets BloodHound
  identifies by name** (`AdminSDHolder`, `DnsAdmins`, Exchange groups, and so on).
- Produces a `mapping.json` that lets you translate masked findings back to real
  names locally with `unmask.py`.

No third-party dependencies. Standard library only. Python 3.8+.

---

## Files

```
houndmasker.py    The command you run (entry point)
masker.py         Masking engine
mapping.py        Token store (writes mapping.json)
safelist.py       Default AD names, Tier Zero named assets, safe SID handling
token_gen.py      Token + numeric SID generation
validate.py       Post-masking validator (optional but recommended)
unmask.py         Reverse-lookup + bulk de-masking of AI output
```

---

## Usage

### First run on a project

```bash
python3 houndmasker.py --new  *.json
```

Processes all the BloodHound JSON files, creates a date-stamped output folder,
and writes a fresh `mapping.json` inside it.

### Continue or re-run the same project

```bash
python3 houndmasker.py --extend  more_files.json
```

`--extend` loads the existing `mapping.json` so the same real name always maps
to the same token across runs. New objects get new tokens, and nothing already
mapped is ever changed.

### Custom output folder

```bash
python3 houndmasker.py --new --outdir ./client_masked  *.json
```

| Flag | Meaning |
|---|---|
| `--new` | First run. Fails if a `mapping.json` already exists in the output folder (prevents accidental overwrite). |
| `--extend` | Continuing a project. Fails if no `mapping.json` is found (prevents an orphaned run). |
| `--outdir DIR` | Output directory. Defaults to `./modified_files_DD_MM_YY` (today's date). |

One of `--new` or `--extend` is always required. They are mutually exclusive.

---

## Output

Running the tool produces, inside the output folder:

```
modified_files_27_06_26/
|-- <original_filename>.json   One masked copy per input file (re-importable)
|-- ...
`-- mapping.json               original -> masked token mapping
```

- The **masked JSON files** are safe to share with an LLM/AI. Import them into a
  clean BloodHound CE instance for analysis, or feed them to your pipeline.
- **`mapping.json` is the sensitive key.** It reverses the masking. Keep it
  local. Never send it to the LLM, and never commit it (it is in `.gitignore`).

---

## What gets masked vs. preserved

**Masked (replaced with a consistent, opaque token)**

- Domain names (FQDNs and NetBIOS)
- Usernames (`name` and `samaccountname`)
- Computer hostnames
- Custom group, OU, GPO, container, CA, and certificate-template names
- Email addresses (masked, but the `user@domain` shape is kept)
- Service Principal Names: the service class (e.g. `MSSQLSvc`) is kept, the host is masked
- Distinguished Names: masked component by component
- The domain portion of every SID (the A-B-C triple in `S-1-5-21-A-B-C-RID`) is swapped for a random numeric triple

**Blanked (emptied completely, 39 fields)**

Free-text, personal, path, and secret fields that routinely hide cleartext
passwords, usernames-in-paths, and PII: `description`, `displayname`, `title`,
`info`, `comment`, `notes`, `givenname`, `surname`, `company`, `department`,
`manager`, `managedby`, office/location fields, phone numbers, `mail`,
home/profile/logon/script paths, and all password fields (`userpassword`,
`unicodepassword`, LAPS `ms-mcs-admpwd`, and so on). If it is free text, it is emptied.

**Preserved (kept verbatim, because BloodHound's analysis needs it)**

- The `meta` block (byte-for-byte, file bookkeeping BloodHound needs to import)
- GUID object identifiers (random, non-identifying keys for GPOs, cert templates, containers, and CAs; every relationship points at them)
- **SID RIDs are never masked:** only the domain triple in the middle of a SID is replaced, so `...-512` rides through
- Well-known SID bodies (`S-1-5-32-544`, `S-1-5-9`, `S-1-1-0`, `S-1-5-11`)
- Default AD group names (`Domain Admins`, `Enterprise Admins`, `BUILTIN`, `SYSTEM`, and so on)
- **Tier Zero assets BloodHound identifies by name rather than SID:** `AdminSDHolder`, `DnsAdmins`, `Exchange Trusted Subsystem` / `Exchange Windows Permissions`, `NTAuthCertificates`, `DHCP Administrators` (universal Microsoft/product defaults, so they leak nothing)
- All boolean, integer, and timestamp properties (`enabled`, `hasspn`, `admincount`, `unconstraineddelegation`, `lastlogon`, and so on)
- Relationship arrays (`Aces`, `Members`, `Sessions`, `LocalGroups`): structure fully intact, only the SIDs/GUIDs inside them are remapped consistently
- `ObjectType` values, certificate thumbprints, OS strings, and OIDs

The result is a structurally identical graph (same users, group nesting, ACLs,
and attack paths) with zero strings that identify your domain, people, or hosts.

> **Note on Tier Zero:** BloodHound re-derives Tier Zero on import. Assets anchored
> to a well-known RID, SID, or object kind (Domain Admins, Administrators, the
> domain, DCs) and the universal name-anchored ones above are preserved for you.
> But Tier Zero you added **manually** in your own instance (for example, tagging
> DnsAdmins) is stored in BloodHound's database, not the JSON, and is keyed to
> identity that masking changes on purpose, so it must be re-applied after
> importing the masked data.

---

## Validating the output

```bash
python3 validate.py --original ../LabFiles --masked ./modified_files_27_06_26
```

Runs eight checks and exits 0 (pass) or 1 (fail):

| Check | Verifies |
|---|---|
| Leak check | No original domain, SID triple, username, computer, or CA name appears in the output (exempts safelisted/preserved names and SPN service classes) |
| SID validity | Every `S-1-5-21-...` SID is numerically valid (re-import safe) |
| Cross-reference | All `Members` object IDs still resolve, no new dangling refs |
| Structure | Object counts and membership counts match the original exactly |
| Meta integrity | `meta` blocks are byte-for-byte unchanged |
| Descriptions | All description fields are blanked |
| PII fields | All 39 free-text/PII fields are blanked |
| ACE preservation | ACE counts preserved per object, well-known SID bodies kept intact |

A dangling-reference *warning* (not a failure) means a member SID points at an
object missing from the source data too, which is a collection gap rather than a
masking error. Run the validator whenever you change masking rules, it catches
regressions immediately.

---

## Reversing the masking (`unmask.py`)

Once an AI has analysed the masked data and given you findings full of tokens,
`unmask.py` translates them back to real names using `mapping.json`.

**Single lookup** (either direction, auto-detected). If a name exists in more
than one place (for example `Administrator` as a User and as an ADCS Cert
Template), it shows **all** matches:

```bash
python3 unmask.py --mapping mapping.json  xKtm-group8      # token to real name
python3 unmask.py --mapping mapping.json  "Administrator"   # real name to token(s)
```

**Bulk translation** is the main workflow. Pipe or paste an AI's analysis and
every token (and fake SID triple) is substituted back in one pass:

```bash
echo "xKtm-user47 has GenericAll on xKtm-group8" | python3 unmask.py --mapping mapping.json
# -> jsmith has GenericAll on IT-Admins

python3 unmask.py --mapping mapping.json --file ai_analysis.txt
```

**Interactive mode** runs with no query and no piped input:

```bash
python3 unmask.py --mapping mapping.json
```

Enter a token or name and press Enter twice to run it. To translate a whole
block, paste it (any number of lines) and end with a blank line, which is handy
for a multi-paragraph AI response. Commands `:stats` and `:quit` run on a single
Enter.

If `--mapping` is omitted it auto-detects `./mapping.json`, then the newest
`./modified_files_*/mapping.json`.

---

## Using it with AI

The masked files are just BloodHound data with the labels swapped, so any workflow
works: paste them into a chat, load them into a clean BloodHound instance, or wire
BloodHound up to an AI over MCP and ask it to reason about attack paths. The blog
walks through the MCP setup end to end. Whatever the AI hands back, run it through
`unmask.py` to get real names.

---

## Disclaimer

Masking is best-effort. Organization-specific edge cases may exist that have not
been encountered yet, so **review the masked output before sharing it**. Grep for
domain names, usernames, or hostnames, or import it back into BloodHound for a few
sanity checks.

This tool is provided as-is, without warranty of any kind, express or implied.
**You are solely responsible for reviewing the masked output and for anything you
choose to share.** The author accepts no responsibility or liability for any data
exposure, leakage, or damage arising from the use of this tool. If you cannot
accept that risk, do not share masked output with third parties.

Found a leak or have an improvement? Open an issue or PR.

---

## Notes

- BloodHound CE stores names in UPPERCASE. The tool matches case-insensitively.
- Token format is `<random-prefix>-<type><number>` (e.g. `xKtm...-user1`) for
  names, and a random numeric triple inside SIDs.
- Re-importing the masked files into BloodHound CE preserves all attack paths,
  group memberships, and ACL relationships.
- Treat `mapping.json` like a credential. It is the only thing that links masked
  tokens back to real identities.

---

Repository: https://github.com/abhisek3122/HoundMasker
