# crypto.py — StealthCrypto v8.1
import base64, hashlib, secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class StealthCrypto:
    @staticmethod
    def gen_keys():
        priv = x25519.X25519PrivateKey.generate()
        pub = priv.public_key()
        return {
            "priv": base64.b64encode(priv.private_bytes_raw()).decode(),
            "pub": base64.b64encode(pub.public_bytes_raw()).decode()
        }

    @staticmethod
    def hash_id(name, pw):
        return hashlib.sha256(f"{name}:{pw}".encode()).hexdigest()

    @staticmethod
    def encrypt_key(chat_key: bytes, pub_hex: str) -> str:
        pub_bytes = bytes.fromhex(pub_hex)
        pub = x25519.X25519PublicKey.from_public_bytes(pub_bytes)
        eph = x25519.X25519PrivateKey.generate()
        shared = eph.exchange(pub)
        derived = HKDF(hashes.SHA256(), 32, None, b"v8").derive(shared)
        aes = AESGCM(derived)
        nonce = secrets.token_bytes(12)
        ct = aes.encrypt(nonce, chat_key, None)
        return base64.b64encode(nonce + eph.public_key().public_bytes_raw() + ct).decode()

    @staticmethod
    def decrypt_key(blob: str, priv_b64: str) -> bytes:
        data = base64.b64decode(blob)
        nonce, eph_pub, ct = data[:12], data[12:44], data[44:]
        eph = x25519.X25519PublicKey.from_public_bytes(eph_pub)
        priv = x25519.X25519PrivateKey.from_private_bytes(base64.b64decode(priv_b64))
        shared = priv.exchange(eph)
        derived = HKDF(hashes.SHA256(), 32, None, b"v8").derive(shared)
        return AESGCM(derived).decrypt(nonce, ct, None)

    @staticmethod
    def enc_msg(text: str, chat_key: bytes):
        nonce = secrets.token_bytes(12)
        aes = AESGCM(chat_key)
        ct = aes.encrypt(nonce, text.encode(), None)
        msg_hash = hashlib.sha256(ct).hexdigest()
        return {
            "ciphertext": base64.b64encode(nonce + ct).decode(),
            "hash": msg_hash
        }

    @staticmethod
    def dec_msg(msg: dict, chat_key: bytes) -> str:
        data = base64.b64decode(msg["ciphertext"])
        nonce, ct = data[:12], data[12:]
        aes = AESGCM(chat_key)
        return aes.decrypt(nonce, ct, None).decode()

    @staticmethod
    def msg_hash(seq, nick, text, time):
        return hashlib.sha256(f"{seq}:{nick}:{text}:{time}".encode()).hexdigest()

    @staticmethod
    def decrypt_raw(hash_input: str, chat_key: bytes):
        # Try to decrypt any valid ciphertext with this key
        try:
            data = base64.b64decode(hash_input)
            if len(data) < 12: return None
            nonce, ct = data[:12], data[12:]
            aes = AESGCM(chat_key)
            return aes.decrypt(nonce, ct, None).decode()
        except:
            return None