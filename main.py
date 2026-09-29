from dictionary_generator import generate_wordlist, save_wordlist
from bruteforce_simulator import hash_password, dictionary_attack, estimate_crack_time
from password_strength_analyzer import analyze_password
from report_generator import ReportBuilder
from hash_extraction import identify_hash


def run_lab_demo():
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


if __name__ == "__main__":
    run_lab_demo()
