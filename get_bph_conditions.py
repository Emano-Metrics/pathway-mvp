import time
import uuid
import requests
import jwt  # PyJWT
from cryptography.hazmat.primitives import serialization

# === 1. CONFIGURATION ===

CLIENT_ID = "4EACE8BE-D2FD-48F1-9378-373CA2E45D29"  # from Veradigm registration
FHIR_BASE = "https://fhir.fhirpoint.open.allscripts.com/fhirroute/open/sandbox"
TOKEN_URL = "https://fhir.fhirpoint.open.allscripts.com/oauth2/token"

# Your private key PEM file (you can also paste it directly as a string)
PRIVATE_KEY_PATH = "private_key.pem"
PRIVATE_KEY_PASSPHRASE = None  # set if your key is encrypted

# === 2. GENERATE SIGNED JWT ===

def load_private_key(path, password=None):
    with open(path, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=password.encode() if password else None,
        )

def generate_jwt(client_id, token_url, private_key):
    now = int(time.time())
    payload = {
        "iss": client_id,
        "sub": client_id,
        "aud": token_url,
        "exp": now + 300,
        "iat": now,
        "jti": str(uuid.uuid4())
    }

    jwt_token = jwt.encode(payload, private_key, algorithm="RS256")
    return jwt_token

# === 3. EXCHANGE JWT FOR ACCESS TOKEN ===

def get_access_token(jwt_token):
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "grant_type": "client_credentials",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": jwt_token,
        "scope": "system/*.read"
    }
    response = requests.post(TOKEN_URL, headers=headers, data=data)
    response.raise_for_status()
    return response.json()["access_token"]

# === 4. GET CONDITIONS FOR BPH (N40.0) ===

def get_bph_conditions(access_token):
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/fhir+json"
    }
    url = f"{FHIR_BASE}/Condition?code=http://hl7.org/fhir/sid/icd-10-cm|N40.0"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

# === MAIN RUN ===

def main():
    private_key = load_private_key(PRIVATE_KEY_PATH, PRIVATE_KEY_PASSPHRASE)
    jwt_token = generate_jwt(CLIENT_ID, TOKEN_URL, private_key)
    access_token = get_access_token(jwt_token)
    print("✅ Access token acquired.")

    data = get_bph_conditions(access_token)
    print("✅ BPH Condition data received.")
    for entry in data.get("entry", []):
        cond = entry["resource"]
        patient_ref = cond.get("subject", {}).get("reference", "Unknown")
        code = cond.get("code", {}).get("coding", [{}])[0].get("code", "Unknown")
        print(f"- Patient: {patient_ref}, Code: {code}")

if __name__ == "__main__":
    main()
