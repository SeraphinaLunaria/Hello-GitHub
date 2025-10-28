#!/usr/bin/env python3
"""
Password Strength Validator
A tool to check password strength against security best practices
"""

import re
import hashlib
from typing import Tuple

# Common passwords to check against (small sample)
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon",
    "baseball", "iloveyou", "master", "sunshine", "ashley",
    "bailey", "passw0rd", "shadow", "123123", "654321"
}


def check_length(password: str) -> Tuple[bool, str]:
    """Check if password meets minimum length requirement"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    elif len(password) < 12:
        return True, "Consider using 12+ characters for better security"
    else:
        return True, "Length requirement met"


def check_complexity(password: str) -> Tuple[bool, str]:
    """Check password complexity requirements"""
    checks = {
        'uppercase': bool(re.search(r'[A-Z]', password)),
        'lowercase': bool(re.search(r'[a-z]', password)),
        'digit': bool(re.search(r'\d', password)),
        'special': bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password))
    }

    missing = [key for key, value in checks.items() if not value]

    if missing:
        return False, f"Missing: {', '.join(missing)}"
    else:
        return True, "Complexity requirements met"


def check_common_passwords(password: str) -> Tuple[bool, str]:
    """Check if password is in common passwords list"""
    if password.lower() in COMMON_PASSWORDS:
        return False, "This is a commonly used password"
    return True, "Not in common passwords list"


def check_patterns(password: str) -> Tuple[bool, str]:
    """Check for common patterns"""
    # Sequential characters
    if re.search(r'(abc|bcd|cde|123|234|345)', password.lower()):
        return False, "Contains sequential characters"

    # Repeated characters
    if re.search(r'(.)\1{2,}', password):
        return False, "Contains repeated characters"

    return True, "No common patterns detected"


def calculate_entropy(password: str) -> float:
    """Calculate password entropy"""
    charset_size = 0

    if re.search(r'[a-z]', password):
        charset_size += 26
    if re.search(r'[A-Z]', password):
        charset_size += 26
    if re.search(r'\d', password):
        charset_size += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        charset_size += 32

    if charset_size == 0:
        return 0

    import math
    entropy = len(password) * math.log2(charset_size)
    return entropy


def check_password_strength(password: str) -> dict:
    """
    Comprehensive password strength check

    Returns:
        dict: Results of all checks
    """
    results = {
        'length': check_length(password),
        'complexity': check_complexity(password),
        'common': check_common_passwords(password),
        'patterns': check_patterns(password),
    }

    # Calculate overall score
    passed = sum(1 for result in results.values() if result[0])
    total = len(results)
    score = int((passed / total) * 100)

    # Calculate entropy
    entropy = calculate_entropy(password)

    results['score'] = score
    results['entropy'] = entropy

    return results


def display_results(password: str, results: dict):
    """Display password strength results"""
    print("\n" + "="*60)
    print("PASSWORD STRENGTH ANALYSIS")
    print("="*60)

    # Hide password partially
    masked = password[0] + "*" * (len(password) - 2) + password[-1] if len(password) > 2 else "**"
    print(f"\nPassword: {masked} (Length: {len(password)})")

    print("\n--- Checks ---")
    for check_name, (passed, message) in results.items():
        if check_name in ['score', 'entropy']:
            continue

        status = "✓" if passed else "✗"
        print(f"{status} {check_name.capitalize():15s}: {message}")

    # Entropy
    print(f"\n--- Entropy ---")
    entropy = results['entropy']
    print(f"Entropy: {entropy:.2f} bits")

    if entropy < 28:
        print("⚠️ Very Weak - Easy to crack")
    elif entropy < 36:
        print("⚠️ Weak - Could be cracked")
    elif entropy < 60:
        print("⚠️ Moderate - Reasonable security")
    elif entropy < 128:
        print("✓ Strong - Good security")
    else:
        print("✓ Very Strong - Excellent security")

    # Overall score
    print(f"\n--- Overall Score ---")
    score = results['score']
    print(f"Score: {score}/100")

    if score < 50:
        print("⚠️ WEAK - Do not use this password")
    elif score < 75:
        print("⚠️ MODERATE - Consider strengthening")
    else:
        print("✓ STRONG - Good password")

    print("\n" + "="*60)


def main():
    """Main function"""
    print("="*60)
    print("PASSWORD STRENGTH VALIDATOR")
    print("="*60)
    print("\nTest your password strength")
    print("Note: Your password is not stored or transmitted\n")

    while True:
        try:
            password = input("Enter password to test (or 'quit' to exit): ")

            if password.lower() == 'quit':
                print("\nGoodbye!")
                break

            if not password:
                print("Please enter a password")
                continue

            results = check_password_strength(password)
            display_results(password, results)

            print("\n--- Recommendations ---")
            if results['score'] < 100:
                print("• Use at least 12 characters")
                print("• Include uppercase and lowercase letters")
                print("• Include numbers and special characters")
                print("• Avoid common words and patterns")
                print("• Use a passphrase or password manager")

        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            break
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    main()
