import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class SecurityError(Exception):
    """密码学安全异常基类"""


class CryptoContext:
    def __init__(self):
        self.private_key = x25519.X25519PrivateKey.generate()
        self.shared_key = None

    def get_public_key(self):
        return self.private_key.public_key().public_bytes_raw()

    def derive_shared_key(self, peer_public_key, salt=None):
        peer_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key)
        shared_secret = self.private_key.exchange(peer_key)

        # 使用HKDF派生密钥
        self.shared_key = HKDF(
            algorithm=hashes.SHA512(),
            length=64,
            salt=salt,
            info=b'file-server-key',
        ).derive(shared_secret)

    def encrypt(self, data):
        iv = os.urandom(12)  # GCM推荐12字节IV
        aes_gcm = AESGCM(self.shared_key[:32])  # 前32字节为加密密钥
        ciphertext = aes_gcm.encrypt(iv, data, self.shared_key[32:])  # 后32字节用于关联数据
        return iv + ciphertext

    def decrypt(self, data):
        iv = data[:12]
        auth_tag = data[-16:]  # GCM固定16字节认证标签
        ciphertext = data[12:-16]

        aes_gcm = AESGCM(self.shared_key[:32])
        try:
            return aes_gcm.decrypt(iv, ciphertext + auth_tag, self.shared_key[32:])
        except Exception as e:
            raise SecurityError("解密失败：可能遭到篡改") from e
