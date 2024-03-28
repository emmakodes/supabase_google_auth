import os
import logging
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("watchfiles").setLevel(logging.WARNING)
from supabase.client import Client
from dotenv import load_dotenv

# load env
load_dotenv()

def supabase_client():
    # setup supabase
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = os.getenv("SUPABASE_KEY")
    client = Client(supabase_url, supabase_key)
    return client
