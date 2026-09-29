import argparse, itertools, string
from pathlib import Path
from datetime import datetime


def name_dob_combos(names, dobs):
    results = set()
    for name in names:
        name = name.strip()
        results.add(name)
        for dob in dobs:
            for d in expand_dob(dob):
                results.add(f"{name}{d}")
                results.add(f"{d}{name}")
                results.add(f"{name}_{d}")
                results.add(f"{name}.{d}")
    return results


def expand_dob(dob):
    variants = {dob}
    digits = "".join(ch for ch in dob if ch.isdigit())
    if len(digits) == 8:
        dd, mm, yyyy = digits[:2], digits[2:4], digits[4:]
        variants.update({dd + mm + yyyy, yyyy, yyyy[-2:], dd + mm, mm + dd,
                         dd + mm + yyyy[-2:]})
    elif len(digits) == 4:
        variants.update({digits, digits[-2:]})
    return variants


def keyboard_patterns():
    return {"qwerty", "asdfgh", "zxcvbn", "qazwsx", "1qaz2wsx",
            "qwertyuiop", "1q2w3e4r", "!qaz2wsx", "poiuyt", "qweasd"}


def load_common_passwords(path=None):
    if path and Path(path).exists():
        with open(path, "r", errors="ignore") as f:
            return {line.strip() for line in f if line.strip()}
    return {"password", "123456", "letmein", "welcome", "admin",
            "iloveyou", "monkey", "dragon", "football", "master"}


def hybrid_combine(word_lists, max_combo=2):
    results = set()
    all_words = set().union(*word_lists)
    for r in range(1, max_combo + 1):
        for combo in itertools.permutations(all_words, r):
            results.add("".join(combo))
    return results


LEET_MAP = {"a": ["4", "@"], "e": ["3"], "i": ["1", "!"],
            "o": ["0"], "s": ["5", "$"], "t": ["7"]}
APPEND_NUMBERS = ["1", "12", "123", "1234", "01", "007", "69", "99", "00"]
APPEND_SYMBOLS = ["!", "@", "#", "$", "*", "!!", "123!"]
CURRENT_YEAR = datetime.now().year
APPEND_YEARS = [str(y) for y in range(CURRENT_YEAR - 5, CURRENT_YEAR + 1)]


def leetspeak_variants(word, max_subs=None):
    positions = [i for i, ch in enumerate(word.lower()) if ch in LEET_MAP]
    if not positions:
        return {word}
    if max_subs:
        positions = positions[:max_subs]
    variants = {word}
    for i in positions:
        ch = word[i].lower()
        new_variants = set()
        for v in variants:
            new_variants.add(v)
            for sub in LEET_MAP[ch]:
                new_variants.add(v[:i] + sub + v[i + 1:])
        variants = new_variants
    return variants


def case_variations(word):
    return {word.lower(), word.upper(), word.capitalize(),
            "".join(c.upper() if i % 2 == 0 else c.lower()
                    for i, c in enumerate(word))}


def append_suffixes(word):
    results = {word}
    for suffix_set in (APPEND_NUMBERS, APPEND_SYMBOLS, APPEND_YEARS):
        for s in suffix_set:
            results.add(word + s)
    return results


def mutate(word, use_leet=True, use_case=True, use_append=True, leet_limit=2):
    pool = {word}
    if use_case:
        expanded = set()
        for w in pool:
            expanded |= case_variations(w)
        pool |= expanded
    if use_leet:
        expanded = set()
        for w in pool:
            expanded |= leetspeak_variants(w, max_subs=leet_limit)
        pool |= expanded
    if use_append:
        expanded = set()
        for w in pool:
            expanded |= append_suffixes(w)
        pool |= expanded
    return pool


def generate_wordlist(names=None, dobs=None, extra_seeds=None,
                      include_keyboard=True, include_common=True,
                      common_list_path=None, apply_mutations=True,
                      max_output=200_000):
    base_words = set()
    if names and dobs:
        base_words |= name_dob_combos(names, dobs)
    if names and not dobs:
        base_words |= set(n.strip() for n in names)
    if include_keyboard:
        base_words |= keyboard_patterns()
    if include_common:
        base_words |= load_common_passwords(common_list_path)
    if extra_seeds:
        base_words |= set(extra_seeds)

    final_list = set(base_words)
    if apply_mutations:
        for w in base_words:
            if not w:
                continue
            final_list |= mutate(w)
            if len(final_list) >= max_output:
                break
    return sorted(final_list)[:max_output]


def save_wordlist(wordlist, out_path):
    with open(out_path, "w") as f:
        for w in wordlist:
            f.write(w + "\n")
    print(f"[+] Saved {len(wordlist)} candidate passwords to {out_path}")


def main():
    parser = argparse.ArgumentParser(description="Lab-only wordlist generator.")
    parser.add_argument("--names", nargs="*", default=[])
    parser.add_argument("--dobs", nargs="*", default=[])
    parser.add_argument("--extra", nargs="*", default=[])
    parser.add_argument("--common-list", default=None)
    parser.add_argument("--no-mutations", action="store_true")
    parser.add_argument("--max", type=int, default=200_000)
    parser.add_argument("--out", default="wordlist.txt")
    args = parser.parse_args()
    wl = generate_wordlist(names=args.names, dobs=args.dobs, extra_seeds=args.extra,
                           common_list_path=args.common_list,
                           apply_mutations=not args.no_mutations, max_output=args.max)
    save_wordlist(wl, args.out)


if __name__ == "__main__":
    main()
