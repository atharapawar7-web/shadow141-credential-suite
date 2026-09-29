"""
gui_app.py
-----------
SHADOW COMPANY 141 — Employee Portal + Credential Attack Console.
Desktop demo app: a fake login portal next to a live attack simulator
running against LOCAL, FICTIONAL demo accounts. Nothing here touches a
real system, network, or real credentials.

Run:  python gui_app.py
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import queue
import time
import datetime

from dictionary_generator import generate_wordlist
from bruteforce_simulator import hash_password, estimate_crack_time
from fake_accounts import ACCOUNTS, PERSONA_HINTS


# ----------------------------
# Color palette
# ----------------------------
BG_MAIN      = "#0d0d14"
BG_PANEL     = "#151521"
BG_INPUT     = "#1f1f2e"
ACCENT       = "#7c5cff"
ACCENT_DIM   = "#4a3a99"
DANGER       = "#ff4d5e"
SUCCESS      = "#33e28a"
WARNING      = "#ffb84d"
TEXT_MAIN    = "#e8e8f0"
TEXT_DIM     = "#8888a0"
LOG_BG       = "#08080d"


def dictionary_attack_live(target_hash, algorithm, wordlist, log_fn,
                            stop_flag, progress_every=250):
    attempts = 0
    start = time.time()
    for candidate in wordlist:
        if stop_flag["stop"]:
            log_fn("[!] Attack aborted by operator.", tag="warn")
            return {"found": False, "attempts": attempts,
                    "elapsed_seconds": round(time.time() - start, 3)}
        attempts += 1
        if hash_password(candidate, algorithm) == target_hash:
            elapsed = round(time.time() - start, 3)
            log_fn(f"[!] MATCH FOUND after {attempts:,} attempts ({elapsed}s)", tag="crit")
            return {"found": True, "password": candidate,
                    "attempts": attempts, "elapsed_seconds": elapsed}
        if attempts % progress_every == 0:
            log_fn(f"[.] Tried {attempts:,} candidates... last: '{candidate}'", tag="dim")
    elapsed = round(time.time() - start, 3)
    return {"found": False, "attempts": attempts, "elapsed_seconds": elapsed}


class CredentialSuiteApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SHADOW COMPANY 141 — Internal Security Lab")
        self.root.geometry("1200x700")
        self.root.configure(bg=BG_MAIN)
        self.root.minsize(1100, 650)

        self._setup_styles()

        self.log_queue = queue.Queue()
        self.stop_flag = {"stop": False}
        self.attack_thread = None

        self._build_header()
        self._build_layout()
        self._build_footer()
        self._poll_log_queue()
        self._tick_clock()

    # ---------------------------------------------------
    # Styling
    # ---------------------------------------------------
    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TCombobox",
                         fieldbackground=BG_INPUT,
                         background=BG_INPUT,
                         foreground=TEXT_MAIN,
                         arrowcolor=ACCENT,
                         borderwidth=0)
        style.map("TCombobox", fieldbackground=[("readonly", BG_INPUT)])
        style.configure("Horizontal.TProgressbar",
                         troughcolor=BG_INPUT,
                         background=ACCENT,
                         thickness=8,
                         borderwidth=0)

    def _build_header(self):
        header = tk.Frame(self.root, bg=BG_PANEL, height=70)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)

        left = tk.Frame(header, bg=BG_PANEL)
        left.pack(side="left", padx=20)
        tk.Label(left, text="🛡  SHADOW COMPANY 141", bg=BG_PANEL, fg=ACCENT,
                  font=("Segoe UI", 18, "bold")).pack(anchor="w", pady=(10, 0))
        tk.Label(left, text="Internal Credential Security Lab — Simulation Environment",
                  bg=BG_PANEL, fg=TEXT_DIM, font=("Segoe UI", 9)).pack(anchor="w")

        right = tk.Frame(header, bg=BG_PANEL)
        right.pack(side="right", padx=20)
        self.clock_label = tk.Label(right, text="", bg=BG_PANEL, fg=TEXT_DIM,
                                     font=("Consolas", 11))
        self.clock_label.pack(anchor="e", pady=(18, 0))

    def _build_footer(self):
        footer = tk.Frame(self.root, bg="#1a0e0e", height=32)
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)
        tk.Label(footer, text="⚠  LAB SIMULATION ONLY — Fictional accounts, local data, "
                               "no real systems or networks involved.",
                  bg="#1a0e0e", fg=WARNING, font=("Segoe UI", 9, "italic")).pack(pady=6)

    def _tick_clock(self):
        now = datetime.datetime.now().strftime("%A, %d %B %Y   %H:%M:%S")
        self.clock_label.config(text=now)
        self.root.after(1000, self._tick_clock)

    # ---------------------------------------------------
    # Main layout
    # ---------------------------------------------------
    def _build_layout(self):
        container = tk.Frame(self.root, bg=BG_MAIN)
        container.pack(fill="both", expand=True, padx=18, pady=18)
        container.columnconfigure(0, weight=0)
        container.columnconfigure(1, weight=1)
        container.rowconfigure(0, weight=1)

        self._build_login_panel(container)
        self._build_attack_panel(container)

    def _build_login_panel(self, parent):
        panel = tk.Frame(parent, bg=BG_PANEL, width=380)
        panel.grid(row=0, column=0, sticky="ns", padx=(0, 18))
        panel.grid_propagate(False)

        tk.Label(panel, text="EMPLOYEE PORTAL", bg=BG_PANEL, fg=TEXT_MAIN,
                  font=("Segoe UI", 14, "bold")).pack(anchor="w", padx=24, pady=(24, 2))
        tk.Label(panel, text="shadow141.corp/login", bg=BG_PANEL, fg=TEXT_DIM,
                  font=("Consolas", 9)).pack(anchor="w", padx=24, pady=(0, 20))

        form = tk.Frame(panel, bg=BG_PANEL)
        form.pack(fill="x", padx=24)

        tk.Label(form, text="USERNAME", bg=BG_PANEL, fg=TEXT_DIM,
                  font=("Segoe UI", 8, "bold")).pack(anchor="w")
        self.username_entry = tk.Entry(form, font=("Segoe UI", 11), bg=BG_INPUT,
                                        fg=TEXT_MAIN, insertbackground=TEXT_MAIN,
                                        relief="flat", highlightthickness=1,
                                        highlightbackground=ACCENT_DIM,
                                        highlightcolor=ACCENT)
        self.username_entry.pack(fill="x", ipady=8, pady=(4, 16))

        tk.Label(form, text="PASSWORD", bg=BG_PANEL, fg=TEXT_DIM,
                  font=("Segoe UI", 8, "bold")).pack(anchor="w")
        self.password_entry = tk.Entry(form, font=("Segoe UI", 11), bg=BG_INPUT,
                                        fg=TEXT_MAIN, insertbackground=TEXT_MAIN,
                                        relief="flat", show="•",
                                        highlightthickness=1,
                                        highlightbackground=ACCENT_DIM,
                                        highlightcolor=ACCENT)
        self.password_entry.pack(fill="x", ipady=8, pady=(4, 20))

        self.login_button = tk.Button(form, text="SIGN IN", font=("Segoe UI", 11, "bold"),
                                       bg=ACCENT, fg="white", relief="flat",
                                       activebackground=ACCENT_DIM, activeforeground="white",
                                       cursor="hand2", command=self.attempt_login)
        self.login_button.pack(fill="x", ipady=10)
        self._add_hover(self.login_button, ACCENT, ACCENT_DIM)

        status_row = tk.Frame(panel, bg=BG_PANEL)
        status_row.pack(fill="x", padx=24, pady=(18, 0))
        self.status_dot = tk.Canvas(status_row, width=12, height=12, bg=BG_PANEL,
                                     highlightthickness=0)
        self.status_dot.pack(side="left")
        self.status_dot_id = self.status_dot.create_oval(2, 2, 10, 10, fill=TEXT_DIM, outline="")
        self.status_label = tk.Label(status_row, text="Awaiting sign-in", bg=BG_PANEL,
                                      fg=TEXT_DIM, font=("Segoe UI", 10, "bold"))
        self.status_label.pack(side="left", padx=8)

        sep = tk.Frame(panel, bg="#242438", height=1)
        sep.pack(fill="x", padx=24, pady=24)

        tk.Label(panel, text="DEMO EMPLOYEE DIRECTORY", bg=BG_PANEL, fg=TEXT_DIM,
                  font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=24)

        acct_frame = tk.Frame(panel, bg=BG_PANEL)
        acct_frame.pack(fill="both", expand=True, padx=24, pady=(8, 20))
        acct_canvas = tk.Canvas(acct_frame, bg=BG_PANEL, highlightthickness=0)
        acct_scroll = ttk.Scrollbar(acct_frame, orient="vertical", command=acct_canvas.yview)
        acct_inner = tk.Frame(acct_canvas, bg=BG_PANEL)
        acct_inner.bind("<Configure>", lambda e: acct_canvas.configure(scrollregion=acct_canvas.bbox("all")))
        acct_canvas.create_window((0, 0), window=acct_inner, anchor="nw")
        acct_canvas.configure(yscrollcommand=acct_scroll.set)
        acct_canvas.pack(side="left", fill="both", expand=True)
        acct_scroll.pack(side="right", fill="y")

        for uname, info in ACCOUNTS.items():
            row = tk.Frame(acct_inner, bg=BG_PANEL)
            row.pack(fill="x", pady=3)
            tk.Label(row, text="●", bg=BG_PANEL, fg=ACCENT, font=("Segoe UI", 8)).pack(side="left")
            tk.Label(row, text=f" {uname}", bg=BG_PANEL, fg=TEXT_MAIN,
                      font=("Consolas", 9, "bold")).pack(side="left")
            tk.Label(row, text=f"  {info['display_name']}", bg=BG_PANEL, fg=TEXT_DIM,
                      font=("Segoe UI", 9)).pack(side="left")

    def _build_attack_panel(self, parent):
        panel = tk.Frame(parent, bg=BG_PANEL)
        panel.grid(row=0, column=1, sticky="nsew")

        head = tk.Frame(panel, bg=BG_PANEL)
        head.pack(fill="x", padx=24, pady=(24, 10))
        tk.Label(head, text="CREDENTIAL ATTACK CONSOLE", bg=BG_PANEL, fg=TEXT_MAIN,
                  font=("Segoe UI", 14, "bold")).pack(anchor="w")
        tk.Label(head, text="OSINT-style dictionary attack simulation against selected account",
                  bg=BG_PANEL, fg=TEXT_DIM, font=("Segoe UI", 9)).pack(anchor="w")

        controls = tk.Frame(panel, bg=BG_PANEL)
        controls.pack(fill="x", padx=24, pady=(10, 6))

        tk.Label(controls, text="TARGET ACCOUNT", bg=BG_PANEL, fg=TEXT_DIM,
                  font=("Segoe UI", 8, "bold")).grid(row=0, column=0, sticky="w")
        self.target_var = tk.StringVar(value=list(ACCOUNTS.keys())[0])
        self.target_dropdown = ttk.Combobox(controls, textvariable=self.target_var,
                                             values=list(ACCOUNTS.keys()),
                                             state="readonly", width=18,
                                             font=("Consolas", 10))
        self.target_dropdown.grid(row=1, column=0, sticky="w", pady=(4, 0), ipady=4)

        self.attack_button = tk.Button(controls, text="⚡ LAUNCH ATTACK", font=("Segoe UI", 10, "bold"),
                                        bg=DANGER, fg="white", relief="flat",
                                        activebackground="#c73a48", activeforeground="white",
                                        cursor="hand2", command=self.start_attack, padx=16, pady=6)
        self.attack_button.grid(row=1, column=1, padx=(14, 8))
        self._add_hover(self.attack_button, DANGER, "#c73a48")

        self.stop_button = tk.Button(controls, text="■ STOP", font=("Segoe UI", 10, "bold"),
                                      bg="#2a2a3d", fg=TEXT_DIM, relief="flat",
                                      cursor="hand2", command=self.stop_attack,
                                      state="disabled", padx=16, pady=6)
        self.stop_button.grid(row=1, column=2)

        self.progress = ttk.Progressbar(panel, mode="indeterminate",
                                         style="Horizontal.TProgressbar")
        self.progress.pack(fill="x", padx=24, pady=(14, 4))

        log_frame = tk.Frame(panel, bg=BG_PANEL)
        log_frame.pack(fill="both", expand=True, padx=24, pady=(10, 24))

        self.log_console = scrolledtext.ScrolledText(
            log_frame, bg=LOG_BG, fg=TEXT_MAIN, font=("Consolas", 10),
            insertbackground=TEXT_MAIN, relief="flat", borderwidth=0, wrap="word"
        )
        self.log_console.pack(fill="both", expand=True)
        self.log_console.configure(state="disabled")

        self.log_console.tag_config("info", foreground="#8aa8ff")
        self.log_console.tag_config("ok", foreground=SUCCESS)
        self.log_console.tag_config("crit", foreground=DANGER, font=("Consolas", 10, "bold"))
        self.log_console.tag_config("warn", foreground=WARNING)
        self.log_console.tag_config("dim", foreground=TEXT_DIM)

    def _add_hover(self, widget, normal, hover):
        widget.bind("<Enter>", lambda e: widget.config(bg=hover))
        widget.bind("<Leave>", lambda e: widget.config(bg=normal))

    # ---------------------------------------------------
    # Login logic
    # ---------------------------------------------------
    def attempt_login(self):
        uname = self.username_entry.get().strip()
        pwd = self.password_entry.get()
        account = ACCOUNTS.get(uname)
        if account and hash_password(pwd, account["hash_algo"]) == account["password_hash"]:
            self.status_label.config(text="ACCESS GRANTED", fg=SUCCESS)
            self.status_dot.itemconfig(self.status_dot_id, fill=SUCCESS)
        else:
            self.status_label.config(text="ACCESS DENIED", fg=DANGER)
            self.status_dot.itemconfig(self.status_dot_id, fill=DANGER)

    # ---------------------------------------------------
    # Logging
    # ---------------------------------------------------
    def log(self, message, tag="info"):
        self.log_queue.put((message, tag))

    def _poll_log_queue(self):
        try:
            while True:
                msg, tag = self.log_queue.get_nowait()
                self.log_console.configure(state="normal")
                self.log_console.insert("end", msg + "\n", tag)
                self.log_console.see("end")
                self.log_console.configure(state="disabled")
        except queue.Empty:
            pass
        self.root.after(100, self._poll_log_queue)

    # ---------------------------------------------------
    # Attack orchestration
    # ---------------------------------------------------
    def start_attack(self):
        if self.attack_thread and self.attack_thread.is_alive():
            return
        self.stop_flag["stop"] = False
        self.attack_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.progress.start(12)
        self.log_console.configure(state="normal")
        self.log_console.delete("1.0", "end")
        self.log_console.configure(state="disabled")

        target_user = self.target_var.get()
        self.attack_thread = threading.Thread(
            target=self._run_attack, args=(target_user,), daemon=True
        )
        self.attack_thread.start()

    def stop_attack(self):
        self.stop_flag["stop"] = True
        self.stop_button.config(state="disabled")

    def _run_attack(self, target_user):
        account = ACCOUNTS[target_user]
        hints = PERSONA_HINTS[target_user]

        self.log(f"[*] Target selected: {target_user}  ({account['display_name']})", "info")
        self.log(f"[*] Stored hash ({account['hash_algo'].upper()}): {account['password_hash']}", "dim")
        self.log("[*] Building attacker wordlist from OSINT-style hints...", "info")
        wordlist = generate_wordlist(
            names=hints["names"], dobs=hints["dobs"], extra_seeds=hints["extra"]
        )
        self.log(f"[+] Generated {len(wordlist):,} candidate passwords.", "ok")
        self.log("[*] Launching dictionary attack against stored hash...", "info")
        self.log("", "dim")

        result = dictionary_attack_live(
            account["password_hash"], account["hash_algo"], wordlist,
            log_fn=self.log, stop_flag=self.stop_flag
        )

        if result["found"]:
            cracked_pw = result["password"]
            self.log(f"[!] PASSWORD CRACKED: '{cracked_pw}'", "crit")
            self.log(f"[!] Attempts: {result['attempts']:,} | Time: {result['elapsed_seconds']}s", "crit")
            self.log("[*] Auto-filling login form with recovered credentials...", "info")
            self.root.after(800, lambda: self._autofill_and_login(target_user, cracked_pw))
        else:
            self.log("[+] Dictionary attack exhausted — password NOT found.", "ok")
            self.log(f"[+] Attempts made: {result['attempts']:,} in {result['elapsed_seconds']}s", "ok")
            self.log("[*] Estimating brute-force time against full keyspace...", "info")
            pw_len = len(account["password_plaintext_DEMO_ONLY"])
            est = estimate_crack_time(charset_size=94, length=pw_len, algorithm="ntlm")
            self.log(f"[+] Assumed attacker speed: {est['hashes_per_second_assumed']:,} hashes/sec (GPU, NTLM)", "dim")
            self.log(f"[+] Worst-case time to crack: {est['worst_case_human']}", "ok")
            self.log(f"[+] Average-case time to crack: {est['average_case_human']}", "ok")
            self.log("[+] Conclusion: This password resists dictionary/OSINT-based attacks.", "ok")

        self.root.after(0, self._attack_finished)

    def _autofill_and_login(self, target_user, password):
        self.username_entry.delete(0, "end")
        self.username_entry.insert(0, target_user)
        self.password_entry.delete(0, "end")
        self.password_entry.insert(0, password)
        self.root.after(500, self.attempt_login)

    def _attack_finished(self):
        self.attack_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.progress.stop()


if __name__ == "__main__":
    root = tk.Tk()
    app = CredentialSuiteApp(root)
    root.mainloop()
