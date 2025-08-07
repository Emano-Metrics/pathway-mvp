from jwcrypto import jwk
import json

# Load your public key PEM file
with open("public_key.pem", "rb") as f:
    key_pem = f.read()

# Convert to JWK object
key = jwk.JWK.from_pem(key_pem)

# Optionally assign a Key ID (required for Veradigm)
key["kid"] = "emano-bph-key"

# Wrap in JWKS format
jwks = {"keys": [key.export(as_dict=True)]}

# Save the JWKS to a file
with open("jwks.json", "w") as out:
    json.dump(jwks, out, indent=2)

print("✅ JWKS file created: jwks.json")
