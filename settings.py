from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

JWT_SECRET = "hardcoded-jwt-secret"
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXP_MINUTES = 30
REFRESH_TOKEN_EXP_MINUTES = 60 * 24 * 30
REFRESH_TOKEN_STORE = BASE_DIR / "refresh_tokens.txt"