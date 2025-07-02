# config.py - Configuration file for the messaging application

import os
import logging

class Config:
    """Configuration class for the messaging application"""
    
    # Server Configuration
    SERVER_HOST = os.getenv('SERVER_HOST', 'localhost')
    SERVER_PORT = int(os.getenv('SERVER_PORT', 9999))
    MAX_CONNECTIONS = int(os.getenv('MAX_CONNECTIONS', 50))
    
    # Database Configuration
    DATABASE_PATH = os.getenv('DATABASE_PATH', 'messaging_server.db')
    
    # File Transfer Configuration
    MAX_FILE_SIZE = int(os.getenv('MAX_FILE_SIZE', 10 * 1024 * 1024))  # 10MB
    ALLOWED_FILE_EXTENSIONS = [
        '.txt', '.pdf', '.doc', '.docx', '.xls', '.xlsx',
        '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg',
        '.mp3', '.wav', '.mp4', '.avi', '.mov'
    ]
    
    # Security Configuration
    PASSWORD_MIN_LENGTH = int(os.getenv('PASSWORD_MIN_LENGTH', 6))
    SESSION_TIMEOUT = int(os.getenv('SESSION_TIMEOUT', 3600))  # 1 hour
    
    # Logging Configuration
    LOG_LEVEL = getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper())
    LOG_FILE = os.getenv('LOG_FILE', 'messaging_app.log')
    
    # Network Configuration
    BUFFER_SIZE = int(os.getenv('BUFFER_SIZE', 4096))
    CONNECTION_TIMEOUT = int(os.getenv('CONNECTION_TIMEOUT', 30))
    
    @classmethod
    def validate_config(cls):
        """Validate configuration parameters"""
        errors = []
        
        if cls.SERVER_PORT < 1024 or cls.SERVER_PORT > 65535:
            errors.append("SERVER_PORT must be between 1024 and 65535")
        
        if cls.MAX_FILE_SIZE < 1024:
            errors.append("MAX_FILE_SIZE must be at least 1024 bytes")
        
        if cls.PASSWORD_MIN_LENGTH < 4:
            errors.append("PASSWORD_MIN_LENGTH must be at least 4")
        
        if errors:
            raise ValueError("Configuration errors: " + "; ".join(errors))
        
        return True


# requirements.txt content
REQUIREMENTS = """
# Core dependencies
tkinter>=8.6  # Usually comes with Python
sqlite3      # Usually comes with Python
socket       # Built-in module
threading    # Built-in module
json         # Built-in module
base64       # Built-in module
hashlib      # Built-in module
logging      # Built-in module
datetime     # Built-in module
os           # Built-in module

# Optional dependencies for enhanced functionality
# Uncomment if needed:
# cryptography>=3.4.8  # For enhanced encryption
# pillow>=8.3.2        # For advanced image processing
# requests>=2.26.0     # For HTTP-based features
"""

# Create requirements.txt file
def create_requirements_file():
    """Create requirements.txt file"""
    with open('requirements.txt', 'w') as f:
        f.write(REQUIREMENTS.strip())
    print("requirements.txt created successfully!")

if __name__ == "__main__":
    # Validate configuration
    try:
        Config.validate_config()
        print("✅ Configuration validation passed!")
    except ValueError as e:
        print(f"❌ Configuration validation failed: {e}")
    
    # Create requirements file
    create_requirements_file()