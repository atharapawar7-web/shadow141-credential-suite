"""
master.py
-----------
SHADOW COMPANY 141 — Master Launcher
Single entry point for the entire Credential Attack Suite.
Run this file, pick a mode from the menu, and it hands off to the
relevant module. No need to remember individual script names.

Run:  python master.py
"""

import sys
import os


def banner():
    print("\n" + "=" * 60)
    print("   SHADOW COMPANY 141 — Credential Security Lab Suite")
    print("=" * 60)
    print("  Lab-only. Fictional data. Authorized targets only.")
    print("=" * 60)


def check_files():
    """Warn early if a required file is missing/empty, instead of a
    confusing traceback halfway through a demo."""
    required = [
        "dictionary_generator.py", "hash_extraction.py",
        "bruteforce_simulator.py", "password_strength_analyzer.py",
        "report_generator.py", "fake_accounts.py",
    ]
    missing_or_empty = []
    for fname in required:
        if not os.path.exists(fname):
            missing_or_empty.append(f"{fname} (missing)")
        elif os.path.getsize(fname) == 0:
            missing_or_empty.append(f"{fname} (empty — 0 bytes)")

    if missing_or_empty:
        print("\n[!] Setup problem detected before launch:")
        for item in missing_or_empty:
            print(f"    - {item}")
        print("\nFix these files first, then rerun master.py.\n")
        return False
    return True


def run_cli_demo():
    print("\n[*] Launching CLI pipeline demo (wordlist -> attack -> report)...\n")
    from dictionary_generator import generate_wordlist, save_wordlist
    from bruteforce_simulator import hash_password, dictionary_attack, estimate_crack_time
    from password_strength_analyzer import analyze_password
    from report_generator import ReportBuilder
    from hash_extraction import identify_hash

    report = ReportBuilder("Intern Lab — Password Policy Assessment")
    wl = generate_wordlist(names=["alex"], dobs=["2001"], extra_seeds=["falcon"])
    save_wordlist(wl, "lab_wordlist.txt")
    report.add_wordlist_stats("lab_wordlist.txt", len(wl))

    for pw in ["alex2001", "Tr0ub4dor&3", "correcthorsebatterystaple123!"]:
        target = hash_password(pw, "md5")
        report.add_hash_findings([{"source": "demo", "algorithm": "MD5",
                                   "identified_as": identify_hash(target)}])
        report.add_bruteforce_result(f"dictionary_attack:{pw}",
                                     dictionary_attack(target, "md5", "lab_wordlist.txt"))
        report.add_strength_analysis(pw, analyze_password(pw, wordlist=wl))

    report.add_bruteforce_result("policy_estimate:12char_full_ntlm",
                                 estimate_crack_time(94, 12, "ntlm"))
    report.save_json("lab_report.json")
    report.save_text("lab_report.txt")
    print("\n[+] Done. See lab_report.txt / lab_report.json for full results.\n")


def run_wordlist_generator():
    from dictionary_generator import generate_wordlist, save_wordlist
    print("\n[*] Custom Wordlist Generator")
    names = input("  Names (space-separated): ").split()
    dobs = input("  DOBs (space-separated, e.g. 1998 14051998): ").split()
    extra = input("  Extra keywords (pet, company, etc.): ").split()
    out = input("  Output filename [wordlist.txt]: ").strip() or "wordlist.txt"

    wl = generate_wordlist(names=names, dobs=dobs, extra_seeds=extra)
    save_wordlist(wl, out)


def run_strength_analyzer():
    from password_strength_analyzer import analyze_password
    import json
    print("\n[*] Password Strength Analyzer")
    pw = input("  Enter password to analyze: ")
    result = analyze_password(pw)
    print(json.dumps(result, indent=2))


def run_hash_identifier():
    from hash_extraction import identify_hash
    print("\n[*] Hash Identifier")
    h = input("  Enter hash string: ").strip()
    print(f"  Possible type(s): {identify_hash(h)}")


def run_crack_time_estimate():
    from bruteforce_simulator import estimate_crack_time, CHARSETS
    print("\n[*] Brute-force Time Estimator")
    print(f"  Available charsets: {list(CHARSETS.keys())}")
    charset = input("  Charset [full]: ").strip() or "full"
    length = int(input("  Password length [12]: ").strip() or "12")
    algo = input("  Hash algorithm (md5/sha256/ntlm/bcrypt) [ntlm]: ").strip() or "ntlm"

    result = estimate_crack_time(len(CHARSETS[charset]), length, algo)
    print(f"\n  Keyspace: {result['keyspace']:,}")
    print(f"  Assumed speed: {result['hashes_per_second_assumed']:,} hashes/sec")
    print(f"  Worst case: {result['worst_case_human']}")
    print(f"  Average case: {result['average_case_human']}")


def run_desktop_gui():
    print("\n[*] Launching Desktop GUI (SHADOW COMPANY 141)...\n")
    try:
        import tkinter as tk
    except ImportError:
        print("[!] tkinter not installed. On Linux: sudo apt install python3-tk")
        return
    from gui_app import CredentialSuiteApp
    root = tk.Tk()
    app = CredentialSuiteApp(root)
    root.mainloop()


def run_web_app():
    print("\n[*] Launching Web App on http://127.0.0.1:5000 ...")
    print("[*] Press Ctrl+C in this terminal to stop the server.\n")
    from app import app as flask_app
    flask_app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)


def run_web_login_tester():
    print("\n[*] Real Login Page Attack Tester")
    print("    Only proceed against systems you own or are explicitly")
    print("    authorized to test.\n")

    confirm = input("  Do you have explicit authorization for this target? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("[!] Authorization not confirmed. Aborting.")
        return

    from web_login_tester import WebLoginTester
    from dictionary_generator import generate_wordlist

    login_url = input("  Login form URL (e.g. http://host/login): ").strip()
    username_field = input("  Username field name (from page source): ").strip()
    password_field = input("  Password field name (from page source): ").strip()
    csrf_field = input("  CSRF hidden field name (blank if none): ").strip() or None
    success_text = input("  Text that ONLY appears on successful login: ").strip()
    target_username = input("  Username to attack: ").strip()

    names_input = input(f"  Known name hints (space-separated) [{target_username}]: ").split()
    if not names_input:
        names_input = [target_username]
    dobs_input = input("  Known DOB/year hints (space-separated): ").split()
    extra_input = input("  Other keyword hints (company, pet, etc.): ").split()

    wordlist = generate_wordlist(names=names_input, dobs=dobs_input, extra_seeds=extra_input)
    print(f"\n[+] Generated {len(wordlist):,} candidate passwords.")

    tester = WebLoginTester(
        login_url=login_url,
        username_field=username_field,
        password_field=password_field,
        csrf_field_name=csrf_field,
        success_indicator=success_text,
        delay_seconds=0.4,
        authorized=True,
    )
    result = tester.dictionary_attack(target_username, wordlist)
    print("\n[+] Result:", result)


MENU = {
    "1": ("Run full CLI pipeline demo (wordlist -> crack -> report)", run_cli_demo),
    "2": ("Generate a custom wordlist", run_wordlist_generator),
    "3": ("Analyze a single password's strength", run_strength_analyzer),
    "4": ("Identify a hash type", run_hash_identifier),
    "5": ("Estimate brute-force crack time", run_crack_time_estimate),
    "6": ("Launch Desktop GUI (fake accounts demo)", run_desktop_gui),
    "7": ("Launch Web App (fake accounts demo, browser)", run_web_app),
    "8": ("Attack a REAL login page (authorized targets only)", run_web_login_tester),
    "0": ("Exit", None),
}


def main():
    banner()
    if not check_files():
        sys.exit(1)

    while True:
        print("\nSelect a mode:\n")
        for key, (label, _) in MENU.items():
            print(f"  [{key}] {label}")
        choice = input("\n> ").strip()

        if choice == "0":
            print("Goodbye.")
            break
        elif choice in MENU:
            _, func = MENU[choice]
            try:
                func()
            except PermissionError as e:
                print(f"[!] {e}")
            except KeyboardInterrupt:
                print("\n[!] Interrupted.")
            except Exception as e:
                print(f"[!] Error while running this mode: {e}")
        else:
            print("[!] Invalid choice, try again.")


if __name__ == "__main__":
    main()
