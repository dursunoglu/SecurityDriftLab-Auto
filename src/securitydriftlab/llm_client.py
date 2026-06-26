import os
from pathlib import Path
from dotenv import load_dotenv
def load_env():
    root = Path(__file__).resolve().parents[2]
    load_dotenv(root/'.env'); load_dotenv()
def has_api_key():
    load_env(); return bool(os.getenv('OPENAI_API_KEY'))
def generate_with_openai(prompt, model=None):
    load_env(); key=os.getenv('OPENAI_API_KEY')
    if not key: raise RuntimeError('NO_API_KEY: Add OPENAI_API_KEY to .env or use manual mode.')
    from openai import OpenAI
    client=OpenAI(api_key=key)
    model=model or os.getenv('OPENAI_MODEL','gpt-4.1-mini')
    r=client.responses.create(model=model, input=prompt, max_output_tokens=2500)
    return r.output_text
