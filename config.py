import os
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")

    HOST = os.getenv("HOST", "127.0.0.1")
    PORT = int(os.getenv("PORT", "5000"))
    DEBUG = os.getenv("DEBUG", "true").lower() == "true"

    NESSUS_URL = os.getenv("NESSUS_URL", "https://localhost:8834")
    NESSUS_ACCESS_KEY = os.getenv("NESSUS_ACCESS_KEY")
    NESSUS_SECRET_KEY = os.getenv("NESSUS_SECRET_KEY")
    NESSUS_VERIFY_SSL = os.getenv("NESSUS_VERIFY_SSL", "false").lower() == "true"