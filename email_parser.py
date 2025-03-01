import re
import email
from bs4 import BeautifulSoup

def extract_email_data(raw_email):
    msg = email.message_from_string(raw_email)
    headers = dict(msg.items())

    # Extract email body
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body = part.get_payload(decode=True).decode(errors="ignore")
    else:
        body = msg.get_payload(decode=True).decode(errors="ignore")

    # Extract links from email
    soup = BeautifulSoup(body, "html.parser")
    links = [a["href"] for a in soup.find_all("a", href=True)]

    return {
        "headers": headers,
        "body": body,
        "links": links
    }
