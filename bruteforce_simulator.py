import hashlib, itertools, string, time, argparse, json


def hash_password(password, algorithm="md5"):
    algorithm = algorithm.lower()
    pw_bytes = password.encode("utf-8")
    if algorithm == "md5":
        return hashlib.md5(pw_bytes).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(pw_bytes).hexdigest()
    elif algorithm == "sha256":
        return hashlib.sha256(pw_bytes).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(pw_bytes).hexdigest()
    elif algorithm == "ntlm":
        return hashlib.new("md4", password.encode("utf-16le")).hexdigest()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


CHARSETS = {
    "lower": string.ascii_lowercase,
    "upper": string.ascii_uppercase,
    "digits": string.digits,
    "symbols": "!@#$%^&*()-_=+",
    "alnum": string.ascii_letters + string.digits,
    "full": string.ascii_letters + string.digits + "!@#$%^&*()-_=+",
}


def incremental_bruteforce(target_hash, algorithm="md5", charset_name="lower",
                           max_length=4, progress_every=100_000):
    charset = CHARSETS[charset_name]
    attempts = 0
    start = time.time()
    for length in range(1, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            candidate = "".join(combo)
            attempts += 1
            if hash_password(candidate, algorithm) == target_hash:
                return {"found": True, "password": candidate, "attempts": attempts,
                        "elapsed_seconds": round(time.time() - start, 4)}
            if attempts % progress_every == 0:
                print(f"[.] {attempts:,} attempts so far...")
    return {"found": False, "attempts": attempts,
            "elapsed_seconds": round(time.time() - start, 4)}


def dictionary_attack(target_hash, algorithm, wordlist_path):
    attempts = 0
    start = time.time()
    with open(wordlist_path, "r", errors="ignore") as f:
        for line in f:
            candidate = line.strip()
            if not candidate:
                continue
            attempts += 1
            if hash_password(candidate, algorithm) == target_hash:
                return {"found": True, "password": candidate, "attempts": attempts,
                        "elapsed_seconds": round(time.time() - start, 4)}
    return {"found": False, "attempts": attempts,
            "elapsed_seconds": round(time.time() - start, 4)}


HASHRATE_ESTIMATES = {
    "md5": 10_000_000_000, "sha1": 4_000_000_000, "sha256": 1_500_000_000,
    "sha512": 500_000_000, "ntlm": 20_000_000_000, "bcrypt": 20_000,
    "sha512crypt": 5_000_000,
}


def estimate_crack_time(charset_size, length, algorithm="md5", hashes_per_second=None):
    if hashes_per_second is None:
        hashes_per_second = HASHRATE_ESTIMATES.get(algorithm.lower(), 1_000_000)
    keyspace = charset_size ** length
    worst = keyspace / hashes_per_second
    return {"keyspace": keyspace, "hashes_per_second_assumed": hashes_per_second,
            "worst_case_human": humanize_seconds(worst),
            "average_case_human": humanize_seconds(worst / 2)}


def humanize_seconds(seconds):
    intervals = [("years", 31_536_000), ("days", 86400), ("hours", 3600),
                 ("minutes", 60), ("seconds", 1)]
    if seconds < 1:
        return "< 1 second"
    parts, remainder = [], seconds
    for name, count in intervals:
        value, remainder = divmod(remainder, count)
        if value >= 1:
            parts.append(f"{int(value)} {name}")
        if len(parts) == 2:
            break
    return ", ".join(parts) if parts else "< 1 second"


def main():
    parser = argparse.ArgumentParser(description="Lab brute-force/dictionary simulator.")
    parser.add_argument("--mode", choices=["bruteforce", "dictionary", "estimate"], required=True)
    parser.add_argument("--password")
    parser.add_argument("--algorithm", default="md5")
    parser.add_argument("--charset", default="lower", choices=CHARSETS.keys())
    parser.add_argument("--max-length", type=int, default=4)
    parser.add_argument("--wordlist")
    parser.add_argument("--length", type=int)
    args = parser.parse_args()

    if args.mode == "estimate":
        print(json.dumps(estimate_crack_time(len(CHARSETS[args.charset]),
                                             args.length, args.algorithm), indent=2))
        return
    target = hash_password(args.password, args.algorithm)
    print(f"[*] Target hash ({args.algorithm}): {target}")
    if args.mode == "bruteforce":
        result = incremental_bruteforce(target, args.algorithm, args.charset, args.max_length)
    else:
        result = dictionary_attack(target, args.algorithm, args.wordlist)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
