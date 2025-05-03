"""
User model and authentication
"""
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin):
    def __init__(self, username):
        self.username = username
        self.id = username  # Use username as ID
        
    @staticmethod
    def get(user_id):
        # For simplicity, we'll use a hardcoded admin user
        # In production, this should use a database
        if user_id == "admin":
            return User("admin")
        return None

# For development, create a simple user store
# In production, use a proper database
users = {
    "admin": generate_password_hash("admin123")  # Default password for testing
} 