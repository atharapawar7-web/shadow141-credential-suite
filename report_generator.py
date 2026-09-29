import json, datetime
from pathlib import Path


class ReportBuilder:
    def __init__(self, project_name="Password Policy Assessment"):
        self.project_name = project_name
        self.timestamp = datetime.datetime.now().isoformat()
        self.wordlist_stats = {}
        self.hash_findings = []
        self.bruteforce_results = []
        self.strength_analyses = []

    def add_wordlist_stats(self, path, count):
        self.wordlist_stats = {"path": path, "entries_generated": count}

    def add_hash_findings(self, findings):
        self.hash_findings.extend(findings)

    def add_bruteforce_result(self, label, result):
        self.bruteforce_results.append({"label": label, **result})

    def add_strength_analysis(self, identifier, analysis):
        self.strength_analyses.append({"identifier": identifier, **analysis})

    def _weak_accounts(self):
        return [a for a in self.strength_analyses
                if a["strength_label"] in ("Very Weak", "Weak")]

    def _recommend_policy(self):
        recs = [
            "Minimum password length: 14+ characters (12 absolute floor).",
            "Require mixed character types OR long passphrases (4+ words).",
            "Block passwords found in known breach/common lists.",
            "Block keyboard-walk and sequential-character patterns.",
            "Enforce unique passwords per system; no reuse.",
            "Enable account lockout / rate limiting after failed attempts.",
            "Use slow, salted hashing (bcrypt/scrypt/argon2), never raw MD5/SHA1/NTLM.",
            "Enforce MFA in addition to password policy.",
        ]
        weak = len(self._weak_accounts())
        if weak:
            recs.insert(0, f"{weak} account(s) flagged Weak/Very Weak — require reset.")
        fast = {f.get("algorithm") for f in self.hash_findings
                if f.get("algorithm") in ("NTLM", "MD5 (crypt)")}
        if fast:
            recs.insert(1, f"Detected fast/legacy hashes ({', '.join(fast)}) — migrate to bcrypt/argon2.")
        return recs

    def to_dict(self):
        return {"project": self.project_name, "generated_at": self.timestamp,
                "wordlist_stats": self.wordlist_stats,
                "hash_findings_summary": {"total_hashes_parsed": len(self.hash_findings),
                                          "details": self.hash_findings},
                "bruteforce_simulation_results": self.bruteforce_results,
                "password_strength_analyses": self.strength_analyses,
                "weak_accounts_flagged": [a["identifier"] for a in self._weak_accounts()],
                "recommended_policy": self._recommend_policy()}

    def save_json(self, path):
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
        print(f"[+] JSON report saved to {path}")

    def save_text(self, path):
        d = self.to_dict()
        lines = [f"=== {d['project']} ===", f"Generated: {d['generated_at']}", "",
                 "-- Wordlist --", str(d['wordlist_stats']), "",
                 "-- Hash Findings --",
                 f"Total parsed: {d['hash_findings_summary']['total_hashes_parsed']}"]
        for h in d["hash_findings_summary"]["details"]:
            lines.append(f"  {h}")
        lines += ["", "-- Simulation Results --"]
        for r in d["bruteforce_simulation_results"]:
            lines.append(f"  {r}")
        lines += ["", "-- Strength Analyses --"]
        for a in d["password_strength_analyses"]:
            lines.append(f"  [{a['identifier']}] {a['strength_label']} "
                         f"(entropy={a['entropy_bits']} bits)")
        lines += ["", "-- Weak Accounts --"]
        lines += [f"  - {acc}" for acc in d["weak_accounts_flagged"]] or ["  None"]
        lines += ["", "-- Recommended Policy --"]
        for rec in d["recommended_policy"]:
            lines.append(f"  * {rec}")
        Path(path).write_text("\n".join(lines))
        print(f"[+] Text report saved to {path}")
