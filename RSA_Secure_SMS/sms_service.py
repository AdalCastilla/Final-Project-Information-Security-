
import os

from pathlib import Path
from dotenv import load_dotenv
from twilio.rest import Client


load_dotenv(Path(__file__).parent / ".env")


def send_sms(ciphertext, recipient):

    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    phone_number = os.getenv("TWILIO_PHONE_NUMBER")

    if not all([account_sid, auth_token, phone_number]):
        raise ValueError("Missing Twilio credentials.")

    client = Client(account_sid, auth_token)

    message = client.messages.create(
        body=ciphertext,
        from_=phone_number,
        to=recipient
    )

    return message
