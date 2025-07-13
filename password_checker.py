#!/usr/bin/env python3
"""
Password Strength Checker
Author: Priyadharshini M A
Description: Analyzes password strength based on length, complexity, and character diversity.
"""

import re

def check_password_strength(password: str) -> dict:
    score = 0
    feedback = []

    # Check length
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("🔸 Password should be at least 8 characters long")

    # Check uppercase
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("🔸 Add at least one uppercase letter")

    # Check lowercase
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("🔸 Add at least one lowercase letter")

    # Check digit
    if re.search(r'[0-9]', password):
        score += 1
    else:
        feedback.append("🔸 Add at least one number")

    # Check symbol
    if re.search(r'[\W_]', password):
        score += 1
    else:
        feedback.append("🔸 Add at least one special character")

    # Repetition or predictable pattern check
    if re.fullmatch(r'(.)\1*', password):
        feedback.append("🔸 Avoid repeating the same character")
        score = 0

    # Final verdict
    if score >= 5:
        verdict = "🟢 Strong"
    elif score >= 3:
        verdict = "🟠 Moderate"
    else:
        verdict = "🔴 Weak"

    return {
        "password": password,
        "score": score,
        "verdict": verdict,
        "suggestions": feedback
    }

def main():
    password = input("Enter a password to check: ")
    result = check_password_strength(password)

    print("\nPassword Analysis ")
    print(f"Password : {'*' * len(password)}")
    print(f"Score    : {result['score']} / 6")
    print(f"Verdict  : {result['verdict']}")

    if result["suggestions"]:
        print("\nSuggestions to improve:")
        for tip in result["suggestions"]:
            print(tip)
    else:
        print("\n✅ Your password is strong!")

if __name__ == "__main__":
    main()
