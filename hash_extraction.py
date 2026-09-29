import re, json, argparse

SHADOW_ALGO_IDS = {"1": "MD5 (crypt)", "2a": "Blowfish (bcrypt)",
                   "2b": "Blowfish (bcrypt)", "5": "SHA-256 (crypt)",
                   "6": "SHA-512 (crypt)", "y": "yescrypt"}


def identify_shadow_hash(hash_field):
    if not hash_field or hash_field in ("*", "!", "!!"):
        return "No password / locked account"
    parts = hash_field.split("$")
    if len(parts) >= 3:
        return SHADOW_ALGO_IDS.get(parts[1], f"Unknown crypt id '{parts[1]}'")
    return "Unrecognized format"


def parse_shadow_file(path):
    entries = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split(":")
            if len(fields) < 2:
                continue
            entries.append({"username": fields[0], "hash_field": fields[1],
                            "algorithm": identify_shadow_hash(fields[1])})
    return entries


PWDUMP_RE = re.compile(
    r"^(?P<user>[^:]+):(?P<rid>\d+):(?P<lm>[0-9A-Fa-f]{32}):(?P<nt>[0-9A-Fa-f]{32}):::")


def parse_pwdump_file(path):
    entries = []
    with open(path, "r") as f:
        for line in f:
            m = PWDUMP_RE.match(line.strip())
            if not m:
                continue
            lm, nt = m.group("lm"), m.group("nt")
            entries.append({"username": m.group("user"), "rid": m.group("rid"),
                            "lm_hash": lm, "nt_hash": nt,
                            "lm_is_empty": lm.upper() == "AAD3B435B51404EEAAD3B435B51404EE",
                            "algorithm": "NTLM"})
    return entries


HASH_PATTERNS = [
    (r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$", "bcrypt"),
    (r"^\$6\$[^$]+\$[./A-Za-z0-9]{86}$", "SHA-512 (crypt)"),
    (r"^\$5\$[^$]+\$[./A-Za-z0-9]{43}$", "SHA-256 (crypt)"),
    (r"^\$1\$[^$]+\$[./A-Za-z0-9]{22}$", "MD5 (crypt)"),
    (r"^[0-9A-Fa-f]{32}$", "MD5 or NTLM (32 hex chars — ambiguous)"),
    (r"^[0-9A-Fa-f]{40}$", "SHA-1"),
    (r"^[0-9A-Fa-f]{64}$", "SHA-256"),
    (r"^[0-9A-Fa-f]{128}$", "SHA-512"),
    (r"^[0-9A-Fa-f]{16}$", "LM hash (half)"),
]


def identify_hash(hash_string):
    hash_string = hash_string.strip()
    matches = [name for pattern, name in HASH_PATTERNS if re.match(pattern, hash_string)]
    return matches if matches else ["Unknown / not recognized"]


def main():
    parser = argparse.ArgumentParser(description="Lab hash parser/identifier.")
    parser.add_argument("--shadow")
    parser.add_argument("--pwdump")
    parser.add_argument("--hash")
    parser.add_argument("--out")
    args = parser.parse_args()
    results = {}
    if args.shadow:
        results["shadow_entries"] = parse_shadow_file(args.shadow)
    if args.pwdump:
        results["pwdump_entries"] = parse_pwdump_file(args.pwdump)
    if args.hash:
        results["hash_identification"] = {args.hash: identify_hash(args.hash)}
    print(json.dumps(results, indent=2))
    if args.out:
        with open(args.out, "w") as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    main()
