import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ========== XOR Encryption ==========
def xor_encrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def xor_decrypt(data, key):
    return xor_encrypt(data, key)  # XOR is symmetric


# ========== AES Encryption ==========
def aes_encrypt(data, key):
    key = key.encode('utf-8').ljust(16, b'\0')[:16]  # pad/truncate to 16 bytes
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes)  # prepend IV

def aes_decrypt(enc_data_b64, key):
    raw = base64.b64decode(enc_data_b64)
    key = key.encode('utf-8').ljust(16, b'\0')[:16]
    iv = raw[:16]
    ct = raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)


# ========== Wrapper Functions ==========
def encrypt_data(data: str, method="none", key="defaultkey"):
    data_bytes = data.encode('utf-8')
    if method == "aes":
        return aes_encrypt(data_bytes, key).decode()
    elif method == "xor":
        return base64.b64encode(xor_encrypt(data_bytes, key.encode())).decode()
    return data  # no encryption

def decrypt_data(enc: str, method="none", key="defaultkey"):
    if method == "aes":
        return aes_decrypt(enc, key).decode()
    elif method == "xor":
        return xor_decrypt(base64.b64decode(enc), key.encode()).decode()
    return enc  # no decryption
