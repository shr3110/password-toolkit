"""
main.py - Password Security Toolkit CLI
Command-line interface for password hashing and validation
"""

import sys
import getpass
from hasher import PasswordHasher, hash_password, verify_password
from validator import PasswordValidator, PasswordPolicy
import json


class PasswordToolkit:
    """Main application class for the Password Security Toolkit"""

    def __init__(self):
        self.hasher = PasswordHasher(rounds=12)
        self.validator = PasswordValidator()
        self.stored_hashes = {}  # Simple in-memory storage for demo

    def display_menu(self):
        """Display the main menu"""
        print("\n" + "=" * 60)
        print("          PASSWORD SECURITY TOOLKIT")
        print("=" * 60)
        print("\n1. Hash a Password")
        print("2. Verify a Password")
        print("3. Validate Password Strength")
        print("4. Test Password Against Policy")
        print("5. Store Password (Hash)")
        print("6. Authenticate User")
        print("7. Configure Password Policy")
        print("8. View Stored Hashes")
        print("9. Password Strength Comparison")
        print("0. Exit")
        print("\n" + "-" * 60)

    def hash_password_menu(self):
        """Hash a password using bcrypt"""
        print("\n--- Hash a Password ---")
        password = getpass.getpass("Enter password to hash: ")

        if not password:
            print("❌ Password cannot be empty")
            return

        print("\nHashing password...")
        hashed = self.hasher.hash_password_bcrypt(password)

        print(f"\n✓ Password hashed successfully!")
        print(f"Hash: {hashed}")

        # Show hash info
        info = self.hasher.get_hash_info(hashed)
        print(f"\nHash Details:")
        print(f"  Algorithm: {info['algorithm']}")
        print(f"  Cost Factor: {info['rounds']}")
        print(f"  Hash Length: {len(hashed)} characters")

    def verify_password_menu(self):
        """Verify a password against a hash"""
        print("\n--- Verify a Password ---")
        password = getpass.getpass("Enter password: ")
        hash_input = input("Enter hash to verify against: ")

        if not password or not hash_input:
            print("❌ Password and hash are required")
            return

        try:
            is_valid = self.hasher.verify_password_bcrypt(password, hash_input)

            if is_valid:
                print("\n✓ Password is VALID! ✓")
            else:
                print("\n✗ Password is INVALID! ✗")
        except Exception as e:
            print(f"\n❌ Error during verification: {e}")

    def validate_strength_menu(self):
        """Validate password strength"""
        print("\n--- Password Strength Analysis ---")
        password = getpass.getpass("Enter password to analyze: ")

        if not password:
            print("❌ Password cannot be empty")
            return

        strength = self.validator.calculate_strength(password)

        # Display strength meter
        print(f"\n{'=' * 60}")
        print(f"Password Strength: {strength['rating']}")
        print(f"Score: {strength['score']}/100")
        self._display_strength_bar(strength['score'])
        print(f"{'=' * 60}")

        # Character analysis
        print("\nCharacter Analysis:")
        print(f"  Length: {strength['length']} characters")
        print(f"  Unique Characters: {strength['unique_chars']}")
        print(f"  Has Uppercase: {'✓' if strength['has_uppercase'] else '✗'}")
        print(f"  Has Lowercase: {'✓' if strength['has_lowercase'] else '✗'}")
        print(f"  Has Digits: {'✓' if strength['has_digits'] else '✗'}")
        print(f"  Has Special: {'✓' if strength['has_special'] else '✗'}")

        # Feedback
        print("\nFeedback:")
        for item in strength['feedback']:
            print(f"  {item}")

        # Suggestions
        suggestions = self.validator.suggest_improvements(password)
        if suggestions and suggestions != ["• Password looks good!"]:
            print("\nSuggestions for Improvement:")
            for suggestion in suggestions:
                print(f"  {suggestion}")

    def _display_strength_bar(self, score):
        """Display a visual strength bar"""
        bar_length = 50
        filled = int((score / 100) * bar_length)
        bar = "█" * filled + "░" * (bar_length - filled)

        # Color coding (using text for cross-platform compatibility)
        if score >= 80:
            color = "STRONG"
        elif score >= 60:
            color = "GOOD"
        elif score >= 40:
            color = "MODERATE"
        else:
            color = "WEAK"

        print(f"[{bar}] {color}")

    def test_policy_menu(self):
        """Test password against policy"""
        print("\n--- Test Password Against Policy ---")
        password = getpass.getpass("Enter password to test: ")

        if not password:
            print("❌ Password cannot be empty")
            return

        is_valid, errors = self.validator.validate(password)

        print(f"\n{'=' * 60}")
        if is_valid:
            print("✓ Password MEETS all policy requirements!")
        else:
            print("✗ Password FAILS policy requirements")
            print("\nViolations:")
            for error in errors:
                print(f"  • {error}")
        print(f"{'=' * 60}")

    def store_password_menu(self):
        """Store a password hash with username"""
        print("\n--- Store Password (Hash) ---")
        username = input("Enter username: ")
        password = getpass.getpass("Enter password: ")

        if not username or not password:
            print("❌ Username and password are required")
            return

        # Validate password first
        is_valid, errors = self.validator.validate(password)

        if not is_valid:
            print("\n✗ Password does not meet policy requirements:")
            for error in errors:
                print(f"  • {error}")

            choice = input("\nStore anyway? (y/n): ").lower()
            if choice != 'y':
                print("❌ Password not stored")
                return

        # Hash and store
        hashed = self.hasher.hash_password_bcrypt(password)
        self.stored_hashes[username] = hashed

        print(f"\n✓ Password stored successfully for user: {username}")

    def authenticate_user_menu(self):
        """Authenticate a user"""
        print("\n--- User Authentication ---")

        if not self.stored_hashes:
            print("❌ No users stored. Please store a password first (option 5)")
            return

        username = input("Enter username: ")
        password = getpass.getpass("Enter password: ")

        if username not in self.stored_hashes:
            print(f"\n✗ User '{username}' not found")
            return

        stored_hash = self.stored_hashes[username]
        is_valid = self.hasher.verify_password_bcrypt(password, stored_hash)

        if is_valid:
            print(f"\n✓ Authentication SUCCESSFUL! Welcome, {username}!")
        else:
            print(f"\n✗ Authentication FAILED! Invalid password for {username}")

    def configure_policy_menu(self):
        """Configure password policy"""
        print("\n--- Configure Password Policy ---")
        print("\nCurrent Policy:")
        self._display_current_policy()

        print("\n1. Use Default Policy")
        print("2. Use Strict Policy")
        print("3. Use Relaxed Policy")
        print("4. Custom Policy")
        print("5. Back to Main Menu")

        choice = input("\nSelect option: ").strip()

        if choice == "1":
            self.validator = PasswordValidator()
            print("\n✓ Default policy applied")
        elif choice == "2":
            strict_policy = PasswordPolicy(
                min_length=12,
                require_uppercase=True,
                require_lowercase=True,
                require_digits=True,
                require_special=True,
                min_uppercase=2,
                min_lowercase=2,
                min_digits=2,
                min_special=2
            )
            self.validator = PasswordValidator(policy=strict_policy)
            print("\n✓ Strict policy applied")
        elif choice == "3":
            relaxed_policy = PasswordPolicy(
                min_length=6,
                require_uppercase=False,
                require_lowercase=True,
                require_digits=True,
                require_special=False
            )
            self.validator = PasswordValidator(policy=relaxed_policy)
            print("\n✓ Relaxed policy applied")
        elif choice == "4":
            self._custom_policy_config()

    def _display_current_policy(self):
        """Display current password policy"""
        policy = self.validator.policy
        print(f"  Min Length: {policy.min_length}")
        print(f"  Max Length: {policy.max_length}")
        print(f"  Require Uppercase: {policy.require_uppercase} (min: {policy.min_uppercase})")
        print(f"  Require Lowercase: {policy.require_lowercase} (min: {policy.min_lowercase})")
        print(f"  Require Digits: {policy.require_digits} (min: {policy.min_digits})")
        print(f"  Require Special: {policy.require_special} (min: {policy.min_special})")

    def _custom_policy_config(self):
        """Configure custom policy"""
        print("\n--- Custom Policy Configuration ---")
        try:
            min_length = int(input("Minimum length (default 8): ") or "8")
            require_upper = input("Require uppercase? (y/n, default y): ").lower() != 'n'
            require_lower = input("Require lowercase? (y/n, default y): ").lower() != 'n'
            require_digits = input("Require digits? (y/n, default y): ").lower() != 'n'
            require_special = input("Require special characters? (y/n, default y): ").lower() != 'n'

            custom_policy = PasswordPolicy(
                min_length=min_length,
                require_uppercase=require_upper,
                require_lowercase=require_lower,
                require_digits=require_digits,
                require_special=require_special
            )

            self.validator = PasswordValidator(policy=custom_policy)
            print("\n✓ Custom policy applied successfully!")
        except ValueError:
            print("\n❌ Invalid input. Policy not changed.")

    def view_stored_hashes_menu(self):
        """View all stored password hashes"""
        print("\n--- Stored Password Hashes ---")

        if not self.stored_hashes:
            print("No passwords stored.")
            return

        print(f"\nTotal Users: {len(self.stored_hashes)}\n")

        for username, hash_value in self.stored_hashes.items():
            info = self.hasher.get_hash_info(hash_value)
            print(f"Username: {username}")
            print(f"  Hash: {hash_value[:50]}...")
            print(f"  Algorithm: {info['algorithm']}")
            print(f"  Rounds: {info['rounds']}\n")

    def password_comparison_menu(self):
        """Compare multiple passwords"""
        print("\n--- Password Strength Comparison ---")
        print("Enter passwords to compare (empty line to finish):\n")

        passwords = []
        i = 1
        while True:
            pwd = getpass.getpass(f"Password {i} (or press Enter to finish): ")
            if not pwd:
                break
            passwords.append(pwd)
            i += 1

        if len(passwords) < 2:
            print("❌ Need at least 2 passwords to compare")
            return

        print(f"\n{'=' * 80}")
        print("COMPARISON RESULTS")
        print(f"{'=' * 80}\n")

        results = []
        for idx, pwd in enumerate(passwords, 1):
            strength = self.validator.calculate_strength(pwd)
            results.append((idx, pwd, strength))

        # Sort by score
        results.sort(key=lambda x: x[2]['score'], reverse=True)

        for rank, (idx, pwd, strength) in enumerate(results, 1):
            print(f"Rank #{rank} - Password {idx}")
            print(f"  Rating: {strength['rating']} ({strength['score']}/100)")
            print(f"  Length: {strength['length']} chars")
            print(f"  Unique: {strength['unique_chars']} chars")
            self._display_strength_bar(strength['score'])
            print()

    def run(self):
        """Main application loop"""
        print("\n🔐 Welcome to the Password Security Toolkit!")
        print("Learn about password hashing, salting, and security policies.")

        while True:
            self.display_menu()

            choice = input("Select an option (0-9): ").strip()

            if choice == "1":
                self.hash_password_menu()
            elif choice == "2":
                self.verify_password_menu()
            elif choice == "3":
                self.validate_strength_menu()
            elif choice == "4":
                self.test_policy_menu()
            elif choice == "5":
                self.store_password_menu()
            elif choice == "6":
                self.authenticate_user_menu()
            elif choice == "7":
                self.configure_policy_menu()
            elif choice == "8":
                self.view_stored_hashes_menu()
            elif choice == "9":
                self.password_comparison_menu()
            elif choice == "0":
                print("\n👋 Thank you for using Password Security Toolkit!")
                print("Stay secure! 🔒\n")
                sys.exit(0)
            else:
                print("\n❌ Invalid option. Please try again.")

            input("\nPress Enter to continue...")


def main():
    """Entry point for the application"""
    try:
        toolkit = PasswordToolkit()
        toolkit.run()
    except KeyboardInterrupt:
        print("\n\n👋 Interrupted by user. Goodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()