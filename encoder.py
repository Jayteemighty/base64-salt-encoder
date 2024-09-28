from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

# Function to derive a salted key
def derive_salted_key(salt_key, salt_index):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_index.to_bytes(16, 'big'),
        iterations=100000,
    )
    derived_key = kdf.derive(salt_key.encode())
    return derived_key

# Function to encode payload
def encode_payload(original_payload, salt_key, salt_index):
    derived_key = derive_salted_key(salt_key, salt_index)
    salt = os.urandom(16)  # Generate a random salt
    payload_with_salt = original_payload.encode() + salt
    encoded = base64.b64encode(payload_with_salt).decode()
    return encoded, salt

# Function to decode payload
def decode_payload(encoded_payload, salt_key, salt_index):
    derived_key = derive_salted_key(salt_key, salt_index)
    
    try:
        decoded_with_salt = base64.b64decode(encoded_payload)
        # Extract the original payload and the salt
        original_payload = decoded_with_salt[:-16]
        salt = decoded_with_salt[-16:]  # Get the salt from the end
        
        # Verify if the salt matches the derived key
        derived_key_for_salt = derive_salted_key(salt_key, salt_index)
        
        if derived_key_for_salt == derived_key:  # Check if keys match
            return original_payload.decode(), True
        else:
            return "Decoding failed: Invalid salt key or salt index", False
    
    except Exception as e:
        return f"Decoding failed: {str(e)}", False

if __name__ == "__main__":
    original_payload = "MySecretPayload"
    salt_key = "mySaltKey"
    salt_index = 1

    encoded, salt = encode_payload(original_payload, salt_key, salt_index)
    print(f"Encoded payload: {encoded}")

    # Decode with correct parameters
    decoded, success = decode_payload(encoded, salt_key, salt_index)
    if success:
        print(f"Decoded payload: {decoded}")
    else:
        print(decoded)

    # Attempt to decode with incorrect parameters
    incorrect_decoded, success = decode_payload(encoded, "wrongSaltKey", salt_index)
    if success:
        print(f"Decoded payload with wrong key: {incorrect_decoded}")
    else:
        print(incorrect_decoded)
