"""Intentionally unsafe examples for testing PyGuard. Do not use as production code."""
import hashlib
import pickle
import subprocess
import requests

def calculate(user_expression: str):
    return eval(user_expression)  # PYG001

def load_user_data(raw: bytes):
    return pickle.loads(raw)  # PYG002

def run_tool(user_argument: str):
    return subprocess.run("echo " + user_argument, shell=True)  # PYG003

def fetch_insecurely(url: str):
    return requests.get(url, verify=False)  # PYG004

API_TOKEN = "sk_live_ABCDEF1234567890"  # PYG005
digest = hashlib.md5(b"sample")  # PYG006
