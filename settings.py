import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "RS256").upper()
JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_PRIVATE_KEY = os.getenv("JWT_PRIVATE_KEY", "")
JWT_PUBLIC_KEY = os.getenv("JWT_PUBLIC_KEY", "")
ACCESS_TOKEN_EXP_MINUTES = 30
REFRESH_TOKEN_EXP_MINUTES = 60 * 24 * 30
REFRESH_TOKEN_STORE = BASE_DIR / "refresh_tokens.txt"
