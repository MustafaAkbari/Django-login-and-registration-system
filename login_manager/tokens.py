# Import necessary modules and classes from Django and the six library.
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from six import text_type

# Define a custom token generator class that extends PasswordResetTokenGenerator.
class TokenGenerator(PasswordResetTokenGenerator):
    # Override the _make_hash_value method to customize token generation.
    def _make_hash_value(self, user: AbstractBaseUser, timestamp: int) -> str:
        # Concatenate user's primary key and timestamp as string representations.
        return (
            text_type(user.pk) + text_type(timestamp)
        )

# Create an instance of the TokenGenerator class.
generate_token = TokenGenerator()
