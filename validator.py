"""
validator.py - Password strength validation and policy enforcement
"""

import re
from typing import List, Dict, Tuple
from dataclasses import dataclass


@dataclass
class PasswordPolicy:
    """Configuration for password requirements"""
    min_length: int = 8
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digits: bool = True
    require_special: bool = True
    min_uppercase: int = 1
    min_lowercase: int = 1
    min_digits: int = 1
    min_special: int = 1
    special_chars: str = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    forbidden_patterns: List[str] = None

    def __post_init__(self):
        if self.forbidden_patterns is None:
            self.forbidden_patterns = []


class PasswordValidator:
    """Validates passwords against security policies"""

    def __init__(self, policy: PasswordPolicy = None):
        """
        Initialize validator with a password policy

        Args:
            policy: PasswordPolicy object (uses defaults if None)
        """
        self.policy = policy or PasswordPolicy()

        # Common weak passwords to check against
        self.common_passwords = {
            'password', '123456', '12345678', 'qwerty', 'abc123',
            'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
            'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
            'bailey', 'passw0rd', 'shadow', '123123', '654321',
            'superman', 'qazwsx', 'michael', 'football', 'password1'
        }

    def validate(self, password: str) -> Tuple[bool, List[str]]:
        """
        Validate a password against all policy rules

        Args:
            password: Password to validate

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        # Check length
        if len(password) < self.policy.min_length:
            errors.append(f"Password must be at least {self.policy.min_length} characters long")

        if len(password) > self.policy.max_length:
            errors.append(f"Password must not exceed {self.policy.max_length} characters")

        # Check uppercase letters
        if self.policy.require_uppercase:
            uppercase_count = sum(1 for c in password if c.isupper())
            if uppercase_count < self.policy.min_uppercase:
                errors.append(f"Password must contain at least {self.policy.min_uppercase} uppercase letter(s)")

        # Check lowercase letters
        if self.policy.require_lowercase:
            lowercase_count = sum(1 for c in password if c.islower())
            if lowercase_count < self.policy.min_lowercase:
                errors.append(f"Password must contain at least {self.policy.min_lowercase} lowercase letter(s)")

        # Check digits
        if self.policy.require_digits:
            digit_count = sum(1 for c in password if c.isdigit())
            if digit_count < self.policy.min_digits:
                errors.append(f"Password must contain at least {self.policy.min_digits} digit(s)")

        # Check special characters
        if self.policy.require_special:
            special_count = sum(1 for c in password if c in self.policy.special_chars)
            if special_count < self.policy.min_special:
                errors.append(f"Password must contain at least {self.policy.min_special} special character(s)")

        # Check for common weak passwords
        if password.lower() in self.common_passwords:
            errors.append("Password is too common and easily guessable")

        # Check for forbidden patterns
        for pattern in self.policy.forbidden_patterns:
            if re.search(pattern, password, re.IGNORECASE):
                errors.append(f"Password contains forbidden pattern")
                break

        # Check for sequential characters
        if self._has_sequential_chars(password):
            errors.append("Password contains sequential characters (e.g., 'abc', '123')")

        # Check for repeated characters
        if self._has_excessive_repeats(password):
            errors.append("Password contains too many repeated characters")

        return len(errors) == 0, errors

    def _has_sequential_chars(self, password: str, min_length: int = 3) -> bool:
        """
        Check if password contains sequential characters

        Args:
            password: Password to check
            min_length: Minimum length of sequence to flag

        Returns:
            True if sequential characters found
        """
        password_lower = password.lower()

        for i in range(len(password_lower) - min_length + 1):
            # Check if characters are sequential (ascending)
            is_sequential = True
            for j in range(min_length - 1):
                if ord(password_lower[i + j + 1]) != ord(password_lower[i + j]) + 1:
                    is_sequential = False
                    break

            if is_sequential:
                return True

            # Check if characters are sequential (descending)
            is_sequential = True
            for j in range(min_length - 1):
                if ord(password_lower[i + j + 1]) != ord(password_lower[i + j]) - 1:
                    is_sequential = False
                    break

            if is_sequential:
                return True

        return False

    def _has_excessive_repeats(self, password: str, max_repeats: int = 3) -> bool:
        """
        Check if password has too many repeated characters

        Args:
            password: Password to check
            max_repeats: Maximum allowed consecutive repeats

        Returns:
            True if excessive repeats found
        """
        count = 1
        for i in range(1, len(password)):
            if password[i] == password[i - 1]:
                count += 1
                if count > max_repeats:
                    return True
            else:
                count = 1

        return False

    def calculate_strength(self, password: str) -> Dict[str, any]:
        """
        Calculate password strength score and provide feedback

        Args:
            password: Password to analyze

        Returns:
            Dictionary with strength score, rating, and feedback
        """
        score = 0
        feedback = []

        # Length scoring
        length = len(password)
        if length >= 16:
            score += 30
            feedback.append("✓ Excellent length")
        elif length >= 12:
            score += 20
            feedback.append("✓ Good length")
        elif length >= 8:
            score += 10
            feedback.append("✓ Adequate length")
        else:
            feedback.append("✗ Too short")

        # Character variety scoring
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in self.policy.special_chars for c in password)

        variety_count = sum([has_upper, has_lower, has_digit, has_special])
        score += variety_count * 15

        if variety_count == 4:
            feedback.append("✓ Excellent character variety")
        elif variety_count >= 3:
            feedback.append("✓ Good character variety")
        else:
            feedback.append("✗ Limited character variety")

        # Entropy bonus
        unique_chars = len(set(password))
        if unique_chars >= len(password) * 0.8:
            score += 10
            feedback.append("✓ High character uniqueness")

        # Penalties
        if password.lower() in self.common_passwords:
            score -= 30
            feedback.append("✗ Common password detected")

        if self._has_sequential_chars(password):
            score -= 15
            feedback.append("✗ Contains sequential characters")

        if self._has_excessive_repeats(password):
            score -= 10
            feedback.append("✗ Contains repeated characters")

        # Determine rating
        score = max(0, min(100, score))

        if score >= 80:
            rating = "Very Strong"
        elif score >= 60:
            rating = "Strong"
        elif score >= 40:
            rating = "Moderate"
        elif score >= 20:
            rating = "Weak"
        else:
            rating = "Very Weak"

        return {
            'score': score,
            'rating': rating,
            'feedback': feedback,
            'has_uppercase': has_upper,
            'has_lowercase': has_lower,
            'has_digits': has_digit,
            'has_special': has_special,
            'length': length,
            'unique_chars': unique_chars
        }

    def suggest_improvements(self, password: str) -> List[str]:
        """
        Suggest improvements for a weak password

        Args:
            password: Password to analyze

        Returns:
            List of improvement suggestions
        """
        suggestions = []
        is_valid, errors = self.validate(password)

        if not is_valid:
            return [f"• {error}" for error in errors]

        strength = self.calculate_strength(password)

        if strength['score'] < 80:
            if strength['length'] < 12:
                suggestions.append("• Consider making it longer (12+ characters)")

            if not strength['has_uppercase']:
                suggestions.append("• Add uppercase letters")

            if not strength['has_lowercase']:
                suggestions.append("• Add lowercase letters")

            if not strength['has_digits']:
                suggestions.append("• Add numbers")

            if not strength['has_special']:
                suggestions.append("• Add special characters (!@#$%^&*)")

            if strength['unique_chars'] < strength['length'] * 0.7:
                suggestions.append("• Use more unique characters")

        return suggestions if suggestions else ["• Password looks good!"]


if __name__ == "__main__":
    # Demo usage
    print("=== Password Validator Demo ===\n")

    # Create validator with default policy
    validator = PasswordValidator()

    test_passwords = [
        "password",
        "Pass123",
        "MyP@ssw0rd",
        "Tr0ub4dor&3",
        "correcthorsebatterystaple",
        "C0mpl3x!P@ssW0rd#2024",
        "abc123",
        "AAAA1111!!!!"
    ]

    for pwd in test_passwords:
        print(f"\nTesting: '{pwd}'")
        print("-" * 50)

        # Validate
        is_valid, errors = validator.validate(pwd)
        print(f"Valid: {is_valid}")

        if errors:
            print("Errors:")
            for error in errors:
                print(f"  • {error}")

        # Calculate strength
        strength = validator.calculate_strength(pwd)
        print(f"\nStrength: {strength['rating']} ({strength['score']}/100)")
        print("Feedback:")
        for item in strength['feedback']:
            print(f"  {item}")

        # Get suggestions
        suggestions = validator.suggest_improvements(pwd)
        if suggestions and suggestions != ["• Password looks good!"]:
            print("\nSuggestions:")
            for suggestion in suggestions:
                print(f"  {suggestion}")

    # Custom policy example
    print("\n\n=== Custom Policy Demo ===")
    custom_policy = PasswordPolicy(
        min_length=12,
        require_special=True,
        min_special=2,
        forbidden_patterns=[r'company', r'admin']
    )

    custom_validator = PasswordValidator(policy=custom_policy)
    test_pwd = "CompanyPass123!"
    is_valid, errors = custom_validator.validate(test_pwd)

    print(f"\nTesting: '{test_pwd}' with custom policy")
    print(f"Valid: {is_valid}")
    if errors:
        print("Errors:")
        for error in errors:
            print(f"  • {error}")