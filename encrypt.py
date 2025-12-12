# encrypt.py
import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PIL import Image

# Crypto params
_SALT_SIZE = 16
_NONCE_SIZE = 12
_KDF_ITERS = 200_000
_KEY_LEN = 32  # 256-bit

def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_LEN,
        salt=salt,
        iterations=_KDF_ITERS,
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_message_b64(password: str, plaintext: str) -> str:
    """
    Returns base64 encoded token: salt || nonce || ciphertext
    """
    salt = os.urandom(_SALT_SIZE)
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(_NONCE_SIZE)
    ct = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    token = salt + nonce + ct
    return base64.b64encode(token).decode('ascii')

def decrypt_message_b64(password: str, token_b64: str) -> str:
    token = base64.b64decode(token_b64)
    if len(token) < (_SALT_SIZE + _NONCE_SIZE + 16):
        raise ValueError("Invalid or corrupted token")
    salt = token[:_SALT_SIZE]
    nonce = token[_SALT_SIZE:_SALT_SIZE + _NONCE_SIZE]
    ct = token[_SALT_SIZE + _NONCE_SIZE:]
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, None)
    return pt.decode('utf-8')

# Simple LSB steganography for text payloads
def _to_bitstream(data_bytes: bytes) -> list:
    bits = []
    for b in data_bytes:
        bits.extend([(b >> i) & 1 for i in range(7, -1, -1)])
    return bits

def _from_bitstream(bits: list) -> bytes:
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        out.append(byte)
    return bytes(out)

def lsb_encode(in_image_path: str, out_image_path: str, payload_str: str) -> None:
    """
    Embed payload_str into image LSB. Adds a 32-bit length prefix.
    """
    img = Image.open(in_image_path)
    img = img.convert('RGBA')  # support alpha to maximize capacity
    pixels = list(img.getdata())

    payload_bytes = payload_str.encode('utf-8')
    length = len(payload_bytes)
    length_bytes = length.to_bytes(4, byteorder='big')
    full = length_bytes + payload_bytes
    bits = _to_bitstream(full)

    capacity = len(pixels) * 4  # using RGBA channels, 1 bit per channel
    if len(bits) > capacity:
        raise ValueError(f"Payload too large. Capacity {capacity//8} bytes, need {len(full)} bytes")

    new_pixels = []
    bit_idx = 0
    for px in pixels:
        r, g, b, a = px
        channels = [r, g, b, a]
        new_ch = []
        for c in channels:
            if bit_idx < len(bits):
                new_c = (c & ~1) | bits[bit_idx]
                bit_idx += 1
            else:
                new_c = c
            new_ch.append(new_c)
        new_pixels.append(tuple(new_ch))

    img.putdata(new_pixels)
    img.save(out_image_path, 'PNG')

def lsb_decode(image_path: str) -> str:
    """
    Extract payload string from image LSB (expects 32-bit length prefix).
    """
    img = Image.open(image_path)
    img = img.convert('RGBA')
    pixels = list(img.getdata())

    bits = []
    for px in pixels:
        for c in px:  # r,g,b,a
            bits.append(c & 1)

    # first 32 bits -> length
    length_bits = bits[:32]
    length_bytes = _from_bitstream(length_bits)
    length = int.from_bytes(length_bytes, byteorder='big')
    total_bits = (4 + length) * 8
    if total_bits > len(bits):
        raise ValueError("Corrupted data or length exceeds capacity")

    payload_bits = bits[32:total_bits]
    payload_bytes = _from_bitstream(payload_bits)
    return payload_bytes.decode('utf-8')

# High-level helpers

def embed_message_aes(in_image_path: str, out_image_path: str, message: str, password: str) -> None:
    """
    Encrypt message with password-derived AES key, embed into image.
    """
    token_b64 = encrypt_message_b64(password, message)
    lsb_encode(in_image_path, out_image_path, token_b64)

def extract_message_aes(encoded_image_path: str, password: str) -> str:
    """
    Extract token from image and decrypt using password.
    """
    token_b64 = lsb_decode(encoded_image_path)
    return decrypt_message_b64(password, token_b64)

# Quick CLI test when run directly
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Embed or extract AES-encrypted messages into images via LSB")
    sub = parser.add_subparsers(dest='cmd')

    e = sub.add_parser('embed')
    e.add_argument('in_image')
    e.add_argument('out_image')
    e.add_argument('password')
    e.add_argument('message')

    d = sub.add_parser('extract')
    d.add_argument('in_image')
    d.add_argument('password')

    args = parser.parse_args()
    if args.cmd == 'embed':
        embed_message_aes(args.in_image, args.out_image, args.message, args.password)
        print("Embedded.")
    elif args.cmd == 'extract':
        print("Message:", extract_message_aes(args.in_image, args.password))
    else:
        parser.print_help()
