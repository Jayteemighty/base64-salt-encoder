import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os

def derive_salted_key(salt_key: str, salt_index: int):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashlib.sha256(),
        length=32,
        salt=salt,
        iterations=salt_index,
        backend=default_backend()
    )
    derived_key = kdf.derive(salt_key.encode())
    return derived_key, salt

def encode_payload(payload: str, salt_key: str, salt_index: int) -> str:
    derived_key, salt = derive_salted_key(salt_key, salt_index)
    combined_payload = payload.encode() + derived_key
    base64_encoded = base64.b64encode(combined_payload)
    return base64_encoded.decode() + '.' + base64.b64encode(salt).decode()

def decode_payload(encoded_payload: str, salt_key: str, salt_index: int) -> str:
    try:
        encoded_data, encoded_salt = encoded_payload.rsplit('.', 1)
        salt = base64.b64decode(encoded_salt)
        decoded_data = base64.b64decode(encoded_data)

        kdf = PBKDF2HMAC(
            algorithm=hashlib.sha256(),
            length=32,
            salt=salt,
            iterations=salt_index,
            backend=default_backend()
        )
        derived_key = kdf.derive(salt_key.encode())
        payload, key_in_payload = decoded_data[:-32], decoded_data[-32:]

        if key_in_payload != derived_key:
            raise ValueError("Invalid salt key or salt index")

        return payload.decode()

    except Exception as e:
        return f"Decoding failed: {str(e)}"

if __name__ == "__main__":
    original_payload = "MySecretPayload"
    salt_key = "supersecretkey"
    salt_index = 10000

    encoded = encode_payload(original_payload, salt_key, salt_index)
    print(f"Encoded payload: {encoded}")

    decoded = decode_payload(encoded, salt_key, salt_index)
    print(f"Decoded payload: {decoded}")

    decoded_fail = decode_payload(encoded, "wrongkey", salt_index)
    print(f"Decoded with wrong key: {decoded_fail}")

    decoded_fail_index = decode_payload(encoded, salt_key, 20000)
    print(f"Decoded with wrong salt index: {decoded_fail_index}")
