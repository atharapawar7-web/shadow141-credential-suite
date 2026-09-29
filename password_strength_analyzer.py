import math, re, argparse, json

COMMON_PATTERNS = ["qwerty", "asdf", "zxcv", "1234", "abcd", "password",
                   "letmein", "admin", "welcome", "iloveyou", "0000", "1111"]
KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]


def calculate_entropy(password):
    pool = 0
    if re.search(r"[a-z]", password): pool += 26
    if re.search(r"[A-Z]", password): pool += 26
    if re.search(r"[0-9]", password): pool += 10
    if re.search(r"[^a-zA-Z0-9]", password): pool += 32
    if pool == 0 or len(password) == 0:
        return 0.0
    return round(len(password) * math.log2(pool), 2)


def check_complexity(password):
    return {"length": len(password),
            "has_lower": bool(re.search(r"[a-z]", password)),
            "has_upper": bool(re.search(r"[A-Z]", password)),
            "has_digit": bool(re.search(r"[0-9]", password)),
            "has_symbol": bool(re.search(r"[^a-zA-Z0-9]", password)),
            "meets_min_length_12": len(password) >= 12}


def detect_keyboard_walk(password):
    lowered = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - 3):
            chunk = row[i:i + 4]
            if chunk in lowered or chunk[::-1] in lowered:
                return True
    return False


def detect_sequential(password):
    for i in range(len(password) - 3):
        codes = [ord(c) for c in password[i:i + 4]]
        if all(codes[j] + 1 == codes[j + 1] for j in range(len(codes) - 1)):
            return True
        if all(codes[j] - 1 == codes[j + 1] for j in range(len(codes) - 1)):
            return True
    return False


def detect_repeated_chars(password, threshold=3):
    return bool(re.search(r"(.)\1{" + str(threshold - 1) + r",}", password))


def detect_common_pattern(password):
    lowered = password.lower()
    return [p for p in COMMON_PATTERNS if p in lowered]


def check_against_wordlist(password, wordlist):
    return password.lower() in {w.lower() for w in wordlist}


def analyze_password(password, wordlist=None):
    complexity = check_complexity(password)
    entropy = calculate_entropy(password)
    flags = {"keyboard_walk": detect_keyboard_walk(password),
             "sequential_chars": detect_sequential(password),
             "repeated_chars": detect_repeated_chars(password),
             "common_patterns_found": detect_common_pattern(password),
             "in_supplied_wordlist": check_against_wordlist(password, wordlist) if wordlist else False}
    score, label = score_password(entropy, complexity, flags)
    return {"password_length": len(password), "complexity": complexity,
            "entropy_bits": entropy, "weakness_flags": flags,
            "score": score, "strength_label": label,
            "suggestions": suggest_improvements(complexity, flags, entropy)}


def score_password(entropy, complexity, flags):
    score = min(entropy / 10, 5)
    score += sum([complexity["has_lower"], complexity["has_upper"],
                  complexity["has_digit"], complexity["has_symbol"]])
    score += 1 if complexity["meets_min_length_12"] else 0
    penalty = sum([flags["keyboard_walk"], flags["sequential_chars"],
                   flags["repeated_chars"], bool(flags["common_patterns_found"]),
                   flags["in_supplied_wordlist"]]) * 2
    score = max(0, round(score - penalty, 2))
    if flags["in_supplied_wordlist"] or score <= 2:
        label = "Very Weak"
    elif score <= 5:
        label = "Weak"
    elif score <= 8:
        label = "Moderate"
    elif score <= 10:
        label = "Strong"
    else:
        label = "Very Strong"
    return score, label


def suggest_improvements(complexity, flags, entropy):
    s = []
    if not complexity["meets_min_length_12"]: s.append("Increase length to at least 12 characters.")
    if not complexity["has_upper"]: s.append("Add uppercase letters.")
    if not complexity["has_lower"]: s.append("Add lowercase letters.")
    if not complexity["has_digit"]: s.append("Add digits.")
    if not complexity["has_symbol"]: s.append("Add symbols.")
    if flags["keyboard_walk"]: s.append("Avoid keyboard-walk patterns.")
    if flags["sequential_chars"]: s.append("Avoid sequential characters.")
    if flags["repeated_chars"]: s.append("Avoid repeating the same character.")
    if flags["common_patterns_found"]: s.append(f"Avoid common substrings: {', '.join(flags['common_patterns_found'])}.")
    if flags["in_supplied_wordlist"]: s.append("Appears in a known wordlist — change immediately.")
    if entropy < 40: s.append("Low entropy — consider a passphrase (4+ random words).")
    if not s: s.append("Password meets baseline strength criteria.")
    return s


def main():
    parser = argparse.ArgumentParser(description="Password strength analyzer.")
    parser.add_argument("--password", required=True)
    parser.add_argument("--wordlist")
    args = parser.parse_args()
    wordlist = None
    if args.wordlist:
        with open(args.wordlist, "r", errors="ignore") as f:
            wordlist = [line.strip() for line in f if line.strip()]
    print(json.dumps(analyze_password(args.password, wordlist), indent=2))


if __name__ == "__main__":
    main()
