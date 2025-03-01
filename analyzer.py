import re
from urllib.parse import urlparse

def analyze_email(email_content):
    score = 0  # Initialize phishing score
    reasons = []  # List to store reasons why the email is suspicious

    # 1️⃣ Suspicious Sender Email (10 points)
    if re.search(r'@[^ ]*(security|alert|verify|support|suspension)[^ ]*\.', email_content, re.IGNORECASE):
        score += 10
        reasons.append("🚨 **Suspicious sender domain detected** (e.g., 'security', 'alert', 'verify').")

    # 2️⃣ Urgency & Fear Keywords (10 points)
    urgency_keywords = ["urgent", "immediate action", "verify now", "final warning", "account locked"]
    if any(word in email_content.lower() for word in urgency_keywords):
        score += 10
        reasons.append("⚠️ **Urgency detected** (e.g., 'Immediate action required', 'Verify now').")

    # 3️⃣ Requests for Personal or Payment Information (10 points)
    sensitive_info_keywords = ["password", "credit card", "cvv", "billing", "ssn", "bank account"]
    if any(word in email_content.lower() for word in sensitive_info_keywords):
        score += 10
        reasons.append("🔑 **Asks for sensitive information** (e.g., password, credit card, billing details).")

    # 4️⃣ Suspicious Links (10 points)
    urls = re.findall(r'https?://\S+', email_content)
    for url in urls:
        parsed_url = urlparse(url)
        if parsed_url.netloc and not parsed_url.netloc.endswith(("paypal.com", "google.com", "amazon.com")):
            score += 10
            reasons.append(f"🔗 **Suspicious link detected**: {url}")
            break  # Only add points once

    # 5️⃣ Shortened Links (10 points)
    shortened_domains = ["bit.ly", "tinyurl.com", "t.co", "goo.gl"]
    if any(short_domain in email_content for short_domain in shortened_domains):
        score += 10
        reasons.append("🔍 **Shortened link detected**, which is often used to hide phishing URLs.")

    # 6️⃣ Poor Grammar or Spelling Errors (10 points)
    grammar_errors = ["dear customer", "your account is suspnded", "click here to vefiry"]
    if any(error in email_content.lower() for error in grammar_errors):
        score += 10
        reasons.append("📝 **Poor grammar or spelling errors detected**, common in phishing emails.")

    # 7️⃣ Fake Company Branding (10 points)
    fake_company_keywords = ["paypal security", "amazon alert", "bank verification"]
    if any(word in email_content.lower() for word in fake_company_keywords):
        score += 10
        reasons.append("🏦 **Fake company branding detected** (e.g., 'PayPal Security', 'Amazon Alert').")

    # 8️⃣ Threatening Language (10 points)
    threatening_keywords = ["legal action", "fine", "lawsuit", "arrest", "account termination"]
    if any(word in email_content.lower() for word in threatening_keywords):
        score += 10
        reasons.append("⚠️ **Threatening language detected** (e.g., 'legal action', 'account termination').")

    # 9️⃣ Too Many Capital Letters (10 points)
    if sum(1 for c in email_content if c.isupper()) > len(email_content) * 0.3:  # More than 30% uppercase
        score += 10
        reasons.append("📢 **Excessive capital letters detected**, often used for scare tactics.")

    # 🔟 Generic Greetings (10 points)
    if re.search(r"(dear customer|dear user|valued customer)", email_content, re.IGNORECASE):
        score += 10
        reasons.append("📩 **Generic greeting detected** (e.g., 'Dear Customer', 'Valued User').")

    # 📊 **Determine Risk Level**
    if score >= 80:
        risk_level = "🚨 **HIGH RISK** - This email is likely a phishing attempt!"
    elif 50 <= score < 80:
        risk_level = "⚠️ **MODERATE RISK** - This email has multiple suspicious indicators."
    else:
        risk_level = "✅ **LOW RISK** - This email appears safe, but still be cautious."

    # 📢 Return results
    return {
        "score": score,
        "risk_level": risk_level,
        "reasons": reasons
    }

