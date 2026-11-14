"""Password Strength Checker + SHA-256 Hashing Demo.

Learning tool only. The password is never stored, sent, or written to
disk — it is scored and hashed in memory, then discarded.

Scoring (0-100):
  length >= 12 : +30, length 8-11 : +15, length < 8 : +0
  has lowercase : +10, has uppercase : +10, has digit : +10,
  has symbol : +15
  not in the common-password list : +15, in the list : -25 (floor 0)
  no 3+ repeated character run : +10

Labels: 0-39 Weak, 40-69 Medium, 70-100 Strong.
"""

import argparse
import hashlib
import re
import sys

# Small local list of the most common weak passwords (for learning only).
COMMON_PASSWORDS = {
    "123456", "123456789", "12345678", "12345", "1234567", "123123",
    "password", "password1", "qwerty", "qwerty123", "abc123", "111111",
    "1234567890", "admin", "letmein", "welcome", "monkey", "dragon",
    "master", "sunshine", "princess", "football", "iloveyou",
}

WEAK = "Weak"
MEDIUM = "Medium"
STRONG = "Strong"


def sha256_hash(password: str) -> str:
    """Return the hex SHA-256 hash of the password (demo of hashing)."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def score_password(password: str) -> dict:
    """Score a password and return the breakdown, label and hash."""
    score = 0
    reasons = []

    length = len(password)
    if length >= 12:
        score += 30
        reasons.append("Length 12+ characters (+30)")
    elif length >= 8:
        score += 15
        reasons.append("Length 8-11 characters (+15)")
    else:
        reasons.append("Too short: under 8 characters (+0)")

    if re.search(r"[a-z]", password):
        score += 10
        reasons.append("Has lowercase letters (+10)")
    else:
        reasons.append("No lowercase letters")
    if re.search(r"[A-Z]", password):
        score += 10
        reasons.append("Has uppercase letters (+10)")
    else:
        reasons.append("No uppercase letters")
    if re.search(r"[0-9]", password):
        score += 10
        reasons.append("Has digits (+10)")
    else:
        reasons.append("No digits")
    if re.search(r"[^A-Za-z0-9]", password):
        score += 15
        reasons.append("Has symbols (+15)")
    else:
        reasons.append("No symbols")

    if password.lower() in COMMON_PASSWORDS:
        score -= 25
        reasons.append("VERY common password (-25) — change it now")
    else:
        score += 15
        reasons.append("Not a common password (+15)")

    if re.search(r"(.)\1\1", password):
        reasons.append("Has 3+ repeated characters in a row (+0)")
    else:
        score += 10
        reasons.append("No long repeated-character runs (+10)")

    score = max(0, min(100, score))
    label = WEAK if score < 40 else (MEDIUM if score < 70 else STRONG)
    return {
        "password_length": length,
        "score": score,
        "label": label,
        "is_common": password.lower() in COMMON_PASSWORDS,
        "sha256": sha256_hash(password),
        "reasons": reasons,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Check a password's strength and show its SHA-256 hash.")
    parser.add_argument("password", help="Password to check (not stored)")
    args = parser.parse_args(argv)

    result = score_password(args.password)
    print(f"Password length : {result['password_length']} characters")
    print(f"Score           : {result['score']}/100")
    print(f"Strength        : {result['label']}")
    if result["is_common"]:
        print("WARNING         : This is one of the most common passwords!")
    print(f"SHA-256 hash    : {result['sha256']}")
    print("Breakdown:")
    for reason in result["reasons"]:
        print(f"  - {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
