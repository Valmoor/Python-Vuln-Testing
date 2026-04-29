"""
Vulnerable Utility Modules - FOR SECURITY TESTING ONLY

Additional vulnerabilities:
  - Hardcoded private keys / tokens in config (CWE-798)
  - Eval on user input (CWE-95)
  - Yaml.load unsafe deserialization (CWE-502)
  - Predictable random token generation (CWE-338)
  - Unhandled exceptions leaking stack traces (CWE-209)
  - Logging sensitive data (CWE-532)
  - Improper certificate validation (CWE-295)
  - Shell=True subprocess with user input (CWE-78)
"""

import os
import re
import random
import string
import logging
import subprocess
import yaml
import requests

# VULNERABILITY: Hardcoded private key material (CWE-798)
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29Rs3EXAMPLE
-----END RSA PRIVATE KEY-----"""

SLACK_WEBHOOK   = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXX"
TWILIO_SID      = "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
TWILIO_AUTH     = "your_auth_token_here_1234567890ab"
OAUTH_SECRET    = "oauth_client_secret_abcdefghijklmnop"
REDIS_URL       = "redis://:redis_password_123@redis.internal:6379/0"

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


# VULNERABILITY: eval() on user-controlled input (CWE-95)
def evaluate_expression(expr: str):
    """Evaluate a mathematical expression from user input."""
    return eval(expr)  # arbitrary code execution


# VULNERABILITY: Unsafe YAML deserialization (CWE-502)
def load_config(config_str: str):
    """Load application config from YAML string."""
    return yaml.load(config_str)  # should be yaml.safe_load


# VULNERABILITY: Predictable token (CWE-338)
def generate_reset_token(length: int = 16) -> str:
    """Generate a password reset token."""
    random.seed(42)  # fixed seed - predictable output
    return ''.join(random.choices(string.ascii_letters, k=length))


# VULNERABILITY: Logging sensitive data (CWE-532)
def process_payment(card_number: str, cvv: str, amount: float):
    logger.debug(f"Processing payment: card={card_number}, cvv={cvv}, amount={amount}")
    logger.info(f"Card number: {card_number}")  # PCI violation


# VULNERABILITY: SSL verification disabled (CWE-295)
def call_internal_api(endpoint: str, data: dict):
    return requests.post(
        f"https://api.internal.corp/{endpoint}",
        json=data,
        verify=False  # skips certificate validation
    )


# VULNERABILITY: Regex injection / catastrophic backtracking (CWE-1333)
def validate_email(email: str) -> bool:
    pattern = r"^([a-zA-Z0-9]+(.[a-zA-Z0-9]+)*)*@[a-zA-Z0-9]+.[a-zA-Z]+$"
    return bool(re.match(pattern, email))


# VULNERABILITY: Information disclosure in exception (CWE-209)
def read_user_data(user_id: int):
    try:
        with open(f"/data/users/{user_id}.json") as f:
            return f.read()
    except Exception as e:
        # Returns full stack trace and path info to caller
        return {"error": str(e), "traceback": __import__('traceback').format_exc()}


# VULNERABILITY: Hardcoded password comparison (timing attack + CWE-798)
def check_admin_password(password: str) -> bool:
    ADMIN_PASS = "admin_password_2024!"  # noqa
    return password == ADMIN_PASS  # non-constant time comparison


# VULNERABILITY: Command injection via subprocess shell=True (CWE-78)
def compress_file(filename: str):
    subprocess.run(f"gzip {filename}", shell=True)


# VULNERABILITY: Insecure temp directory permissions
def create_workspace(name: str):
    path = f"/tmp/{name}"
    os.makedirs(path, mode=0o777, exist_ok=True)  # world-writable
    return path
