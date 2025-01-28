from datetime import datetime, timedelta, UTC

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from core.database.models import User
from core.exception import *


class AuthService:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    async def init_keys(self):
        """生成或加载RSA密钥对"""
        # 实际应存储到安全位置，这里示例生成新密钥

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024
        )
        self.private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        self.public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def generate_token(self, user_id: int, token_version: int) -> str:
        """生成JWT令牌"""
        payload = {
            "sub": str(user_id),
            "exp": datetime.now(UTC) + timedelta(hours=1),
            "iat": datetime.now(UTC),
            "version": token_version
        }
        return jwt.encode(payload, self.private_key, algorithm="RS256")

    async def verify_token(self, token: str) -> dict:
        """返回修改后的验证方法"""
        try:
            payload = jwt.decode(
                token,
                self.public_key,
                algorithms=["RS256"],
                options={"require": ["exp", "iat", "sub"]}
            )

            # 检查令牌版本
            user = await User.get(id=payload["sub"])
            if user.token_version != payload["version"]:
                raise InvalidTokenError("令牌版本不匹配")

            return payload
        except jwt.ExpiredSignatureError:
            raise TokenExpiredError()
        except jwt.InvalidTokenError as e:
            raise InvalidTokenError(str(e))
        except Exception as e:
            raise AppException(f"令牌验证失败: {str(e)}")
