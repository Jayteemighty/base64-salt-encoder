## Base64 Salt Encoder

This project implements a Python program to encode and decode payloads using Base64, a salt key, and a salt index. The program ensures that the payload can only be decoded correctly with the correct salt key and index.

## Features

- Encode any payload into Base64 with a salt key and index.
- Decode the payload using the same salt key and index.
- Properly fails if an incorrect salt key or index is used.

## Requirements

- Python 3.x
- cryptography module

You can install the required module using:

```bash
pip install cryptography

python encoder.py
