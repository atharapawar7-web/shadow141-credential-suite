import random, string
from bruteforce_simulator import hash_password

FIRST_NAMES = ["Rohan", "Ananya", "Vikram", "Sneha", "Arjun", "Kavya", "Devansh",
               "Aditya", "Priya", "Karan", "Divya", "Rahul", "Neha", "Siddharth",
               "Pooja", "Manish", "Ishita", "Aryan", "Riya", "Nikhil"]
LAST_NAMES = ["Sharma", "Patel", "Gupta", "Pillai", "Reddy", "Iyer", "Singh",
              "Verma", "Nair", "Mehta", "Rao", "Kapoor", "Joshi", "Desai",
              "Chauhan", "Bose", "Malhotra", "Sen", "Bansal", "Kulkarni"]
CITY_KEYWORDS = ["mumbai", "delhi", "bangalore", "chennai", "hyderabad",
                 "pune", "kolkata", "jaipur"]
COMPANY = "shadow141"

NUM_ACCOUNTS = 5
NUM_STRONG_ACCOUNTS = 2
random.seed(42)


def make_username(first, last, existing):
    base = (first[0] + last).lower()
    username, counter = base, 2
    while username in existing:
        username = f"{base}{counter}"; counter += 1
    return username


def random_dob():
    year = random.randint(1985, 2001)
    day, month = random.randint(1, 28), random.randint(1, 12)
    return f"{day:02d}{month:02d}{year}", str(year)


def random_strong_password(length=16):
    pool = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(random.choice(pool) for _ in range(length))


def generate_account(first, last, existing, strong=False):
    username = make_username(first, last, existing)
    dob_full, dob_year = random_dob()
    extra = random.sample(CITY_KEYWORDS, 2) + [COMPANY]
    if strong:
        password = random_strong_password()
    else:
        password = f"{first.lower()}{dob_year}{random.choice(['!', '@', '123', '#1', ''])}"
    account = {"display_name": f"{first} {last}",
               "password_plaintext_DEMO_ONLY": password,
               "password_hash": hash_password(password, "md5"), "hash_algo": "md5"}
    hints = {"names": [username, first.lower(), last.lower()],
             "dobs": [dob_year, dob_full], "extra": extra}
    return username, account, hints


name_pairs = list(zip(FIRST_NAMES, LAST_NAMES))
random.shuffle(name_pairs)
name_pairs = name_pairs[:NUM_ACCOUNTS]

ACCOUNTS, PERSONA_HINTS = {}, {}
for i, (first, last) in enumerate(name_pairs):
    is_strong = i >= (NUM_ACCOUNTS - NUM_STRONG_ACCOUNTS)
    username, account, hints = generate_account(first, last, ACCOUNTS.keys(), is_strong)
    ACCOUNTS[username] = account
    PERSONA_HINTS[username] = hints
