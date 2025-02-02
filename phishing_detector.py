from flask import Flask, request, jsonify
from flask_cors import CORS
import openai
import os
import requests
from dotenv import load_dotenv
import re

load_dotenv()

app = Flask(__name__)
CORS(app)

openai_api_key = os.getenv("OPENAI_API_KEY")
google_api_key = os.getenv("GOOGLE_API_KEY")

if not openai_api_key:
    raise ValueError("❌ ERROR: Missing OPENAI_API_KEY")
if not google_api_key:
    raise ValueError("❌ ERROR: Missing GOOGLE_API_KEY")
openai.api_key = openai_api_key
###############################################################################
#                               HELPER FUNCTIONS                              #
###############################################################################
def parse_input_for_url_or_email(text):
    text = text.strip()

    # Check if it's possibly an email
    email_pattern = r"^[^@]+@[^@]+\.[^@]+$"
    if re.match(email_pattern, text, re.IGNORECASE):
        return {"type": "email", "value": text}

    # If not an email, see if it looks like a domain or starts with http(s)://
    domain_like_pattern = r"^[\w.-]+\.[a-zA-Z]{2,}$"

    if text.lower().startswith("http://") or text.lower().startswith("https://"):
        return {"type": "url", "value": text}
    else:
        if re.match(domain_like_pattern, text) or text.lower().startswith("www."):
            return {"type": "url", "value": f"http://{text}"}
        else:
            return {"type": "text", "value": text}


def check_google_safe_browsing(url):
    """
    Check if a URL is flagged using Google Safe Browsing.
    Returns a dict with 'status': ("SAFE", "UNSAFE", or "UNKNOWN").
    """
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={google_api_key}"
    payload = {
        "client": {"clientId": "safenet", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = requests.post(api_url, json=payload, timeout=8)
        result = response.json()
    except Exception as e:
        return {"status": "UNKNOWN", "info": f"Error calling Safe Browsing: {str(e)}"}

    if "matches" in result:
        return {"status": "UNSAFE", "info": "Flagged by Google Safe Browsing"}
    else:
        return {"status": "SAFE", "info": "No flags from Google Safe Browsing"}


def is_legit_email(email):
    trusted_domains = {
        "apple.com": "Apple",
        "icloud.com": "Apple",
        "google.com": "Google",
        "gmail.com": "Google",
        "outlook.com": "Microsoft",
        "microsoft.com": "Microsoft",
        "yahoo.com": "Yahoo",
        "bankofamerica.com": "Bank of America",
        "chase.com": "Chase Bank",
        "wellsfargo.com": "Wells Fargo",
        "paypal.com": "PayPal",
        "irs.gov": "IRS",
        "gov.uk": "UK Government",
        "amazon.com": "Amazon",
        "ebay.com": "eBay",
        "twitter.com": "X/Twitter",
        "x.com": "X/Twitter",
        "facebook.com": "Facebook",
        "linkedin.com": "LinkedIn"
    }
    domain = email.split("@")[-1].lower()
    if domain in trusted_domains:
        return f"Trusted domain: {trusted_domains[domain]}"
    else:
        return f"Unrecognized or untrusted domain: {domain}"

def get_email_trust_score(email):
    """
    Assign a numeric trust score to the email based on domain and suspicious keywords.
    """
    score = 100
    suspicious_keywords = ["secure", "verify", "update", "login", "support", "account", "billing", "service"]

    if "Unrecognized" in is_legit_email(email):
        score -= 50

    if any(word in email.lower() for word in suspicious_keywords):
        score -= 20

    return score
###############################################################################
#                               FLASK ROUTES                                  #
###############################################################################

@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Flask Backend is Running!"}), 200


@app.route("/detect_phishing", methods=["POST"])
def detect_phishing():
    try:
        data = request.get_json()
        if not data or "text" not in data:
            return jsonify({"error": "Invalid request payload"}), 400

        user_input = data["text"].strip()
        parsed = parse_input_for_url_or_email(user_input)

        #######################################################################
        # CASE 1: URL
        #######################################################################
        if parsed["type"] == "url":
            sb_result = check_google_safe_browsing(parsed["value"])
            if sb_result["status"] == "UNSAFE":
                return jsonify({"analysis": "DANGER"}), 200
            elif sb_result["status"] == "UNKNOWN":
                # If there's an error calling Safe Browsing, you can label it "SUSPICIOUS" or "UNKNOWN"
                return jsonify({"analysis": "SUSPICIOUS: Unable to verify via Google Safe Browsing."}), 200
            else:
                # If "SAFE"
                return jsonify({"analysis": "SAFE"}), 200

        #######################################################################
        # CASE 2: EMAIL
        #######################################################################
        elif parsed["type"] == "email":
            domain_result = is_legit_email(parsed["value"])
            score = get_email_trust_score(parsed["value"])
            rating = "Safe" if score >= 80 else ("Suspicious" if 50 <= score < 80 else "Danger")
            analysis_msg = f"{rating} ({score}/100) - {domain_result}"
            return jsonify({"analysis": analysis_msg}), 200

        #######################################################################
        # CASE 3: GENERAL TEXT
        #######################################################################
        else:
            # For text that isn't a URL or email, call GPT (optional)
            prompt = (
                "You are a cybersecurity expert. The user wrote this text:\n\n"
                f"{parsed['value']}\n\n"
                "Give a concise verdict (SAFE, DANGER, or SUSPICIOUS) plus a short reason. Keep response below 2 sentences."
            )
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert analyzing potential phishing attempts."},
                    {"role": "user", "content": prompt},
                ]
            )
            gpt_msg = response.choices[0].message.content.strip()
            return jsonify({"analysis": gpt_msg}), 200

    except Exception as e:
        print(f"❌ ERROR in /detect_phishing: {str(e)}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
