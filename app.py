"""
app.py
-------
SHADOW COMPANY 141 — Web-based Employee Portal + Credential Attack Console.
Local Flask app for lab demo purposes. Runs on localhost (or your local
network for a live room demo) — not intended for public internet deployment.
"""

import json
import time
from flask import Flask, render_template, request, jsonify, Response

from dictionary_generator import generate_wordlist
from bruteforce_simulator import hash_password, estimate_crack_time
from fake_accounts import ACCOUNTS, PERSONA_HINTS

app = Flask(__name__)


def sse(data):
    return f"data: {json.dumps(data)}\n\n"


def dictionary_attack_stream(target_hash, algorithm, wordlist, progress_every=500):
    attempts = 0
    start = time.time()
    for candidate in wordlist:
        attempts += 1
        if hash_password(candidate, algorithm) == target_hash:
            elapsed = round(time.time() - start, 3)
            yield {"type": "match", "password": candidate,
                   "attempts": attempts, "elapsed": elapsed}
            return
        if attempts % progress_every == 0:
            yield {"type": "progress", "attempts": attempts, "last": candidate}
    elapsed = round(time.time() - start, 3)
    yield {"type": "exhausted", "attempts": attempts, "elapsed": elapsed}


@app.route("/")
def index():
    accounts_list = [
        {"username": u, "display_name": info["display_name"]}
        for u, info in ACCOUNTS.items()
    ]
    return render_template("index.html", accounts=accounts_list,
                            company="SHADOW COMPANY 141")


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    account = ACCOUNTS.get(username)
    success = bool(
        account and hash_password(password, account["hash_algo"]) == account["password_hash"]
    )
    return jsonify({"success": success})


@app.route("/attack/<username>")
def attack(username):
    def generate():
        account = ACCOUNTS.get(username)
        if not account:
            yield sse({"type": "error", "message": "Unknown account."})
            return

        hints = PERSONA_HINTS[username]

        yield sse({"type": "log", "tag": "info",
                   "message": f"Target selected: {username} ({account['display_name']})"})
        time.sleep(0.4)
        yield sse({"type": "log", "tag": "dim",
                   "message": f"Stored hash ({account['hash_algo'].upper()}): {account['password_hash']}"})
        time.sleep(0.4)
        yield sse({"type": "log", "tag": "info",
                   "message": "Building attacker wordlist from OSINT-style hints..."})

        wordlist = generate_wordlist(
            names=hints["names"], dobs=hints["dobs"], extra_seeds=hints["extra"]
        )
        time.sleep(0.4)
        yield sse({"type": "log", "tag": "ok",
                   "message": f"Generated {len(wordlist):,} candidate passwords."})
        time.sleep(0.3)
        yield sse({"type": "log", "tag": "info",
                   "message": "Launching dictionary attack against stored hash..."})
        time.sleep(0.3)

        found_result = None
        for event in dictionary_attack_stream(account["password_hash"],
                                               account["hash_algo"], wordlist):
            if event["type"] == "progress":
                yield sse({"type": "log", "tag": "dim",
                           "message": f"Tried {event['attempts']:,} candidates... "
                                      f"last: '{event['last']}'"})
                time.sleep(0.08)
            elif event["type"] == "match":
                found_result = event
                yield sse({"type": "log", "tag": "crit",
                           "message": f"PASSWORD CRACKED: '{event['password']}'"})
                time.sleep(0.3)
                yield sse({"type": "log", "tag": "crit",
                           "message": f"Attempts: {event['attempts']:,} | Time: {event['elapsed']}s"})
                time.sleep(0.3)
            elif event["type"] == "exhausted":
                yield sse({"type": "log", "tag": "ok",
                           "message": "Dictionary attack exhausted — password NOT found."})
                time.sleep(0.3)
                yield sse({"type": "log", "tag": "ok",
                           "message": f"Attempts made: {event['attempts']:,} in {event['elapsed']}s"})
                time.sleep(0.3)
                yield sse({"type": "log", "tag": "info",
                           "message": "Estimating brute-force time against full keyspace..."})
                pw_len = len(account["password_plaintext_DEMO_ONLY"])
                est = estimate_crack_time(charset_size=94, length=pw_len, algorithm="ntlm")
                time.sleep(0.3)
                yield sse({"type": "log", "tag": "dim",
                           "message": f"Assumed attacker speed: "
                                      f"{est['hashes_per_second_assumed']:,} hashes/sec (GPU, NTLM)"})
                time.sleep(0.2)
                yield sse({"type": "log", "tag": "ok",
                           "message": f"Worst-case time to crack: {est['worst_case_human']}"})
                time.sleep(0.2)
                yield sse({"type": "log", "tag": "ok",
                           "message": f"Average-case time to crack: {est['average_case_human']}"})
                time.sleep(0.2)
                yield sse({"type": "log", "tag": "ok",
                           "message": "Conclusion: resists dictionary/OSINT-based attacks."})

        if found_result:
            yield sse({"type": "done", "cracked": True,
                       "username": username, "password": found_result["password"]})
        else:
            yield sse({"type": "done", "cracked": False})

    return Response(generate(), mimetype="text/event-stream")


if __name__ == "__main__":
    # host="0.0.0.0" lets other devices on your WiFi open this too (for room demos).
    # Keep this OFF the public internet — local network / localhost only.
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)
