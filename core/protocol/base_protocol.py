import asyncio
import gzip
import logging
import os
from enum import Enum

import lz4.frame as lz4

from utils.crypto import CryptoContext


class CFMCBaseConnection:
    """连接基类"""
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    crypto: CryptoContext | None = None


class ConnectionFlag(int, Enum):
    """压缩标志枚举"""
    NoZip = 0
    Lz4 = 1
    Gzip = 2
    Heartbeat = 3
    Control = 4


class CFMSProtocolError(Exception):
    """协议违反异常"""
    pass


class CFMSBaseProtocol:
    def __init__(
            self,
            max_frame_size: int = 1 * 1024 * 1024 * 1024,  # 1GB
            compression_flag: ConnectionFlag = ConnectionFlag.Lz4,
            logger: logging.Logger = logging.getLogger(f"{__name__}.CFMSProtocol")
    ):
        self.max_frame_size = max_frame_size
        self.compression_flag = compression_flag
        self.logger = logger

    async def server_side_shake_hand(self, conn: CFMCBaseConnection):
        """
        ECC密钥交换，服务器侧
        """
        conn.crypto = CryptoContext()  # 每个客户端的密钥不同，绑定到每个连接上
        try:
            # 发送服务器临时公钥
            server_public_key = conn.crypto.get_public_key()
            conn.writer.write(server_public_key)
            await conn.writer.drain()

            # 接收客户端临时公钥
            client_public_key = await conn.reader.readexactly(32)
            if len(client_public_key) != 32:
                raise CFMSProtocolError("Invalid client public key length")

            # 交换盐值，防止两端盐值不相同报错
            salt = os.urandom(32)
            conn.writer.write(salt)
            await conn.writer.drain()

            # 密钥派生与验证
            conn.crypto.derive_shared_key(client_public_key, salt=salt)

            # 握手确认阶段
            # 生成，发送，接收，检验随机挑战值
            challenge = os.urandom(16)
            encrypted_challenge = conn.crypto.encrypt(challenge)
            conn.writer.write(encrypted_challenge)
            await conn.writer.drain()
            client_response = await conn.reader.readexactly(len(encrypted_challenge))
            decrypted_response = conn.crypto.decrypt(client_response)
            if decrypted_response != challenge:
                raise CFMSProtocolError("Handshake challenge verification failed")

        except asyncio.IncompleteReadError as e:
            self.logger.error(f"Handshake failed: {str(e)}")
            conn.writer.close()
            raise CFMSProtocolError("Incomplete handshake data")

    async def client_side_shake_hand(self, conn: CFMCBaseConnection):
        """
        ECC密钥交换，客户端侧
        """
        try:
            # 临时密钥生成
            conn.crypto = CryptoContext()  # 每次连接创建新实例

            # ECDH密钥交换
            # 接收服务器公钥
            server_public_key = await conn.reader.readexactly(32)
            if len(server_public_key) != 32:
                raise CFMSProtocolError("Invalid server public key length")

            # 发送客户端临时公钥
            client_public_key = conn.crypto.get_public_key()
            conn.writer.write(client_public_key)
            await conn.writer.drain()

            salt = await conn.reader.readexactly(32)

            # 密钥派生
            conn.crypto.derive_shared_key(server_public_key, salt=salt)
            # 握手确认阶段
            # 接收，解密，发送挑战值
            encrypted_challenge = await conn.reader.readexactly(44)  # 16字节数据+GCM填充+vi
            challenge = conn.crypto.decrypt(encrypted_challenge)
            encrypted_response = conn.crypto.encrypt(challenge)
            conn.writer.write(encrypted_response)
            await conn.writer.drain()

        except asyncio.IncompleteReadError as e:
            self.logger.error(f"Handshake failed: {str(e)}")
            conn.writer.close()
            raise CFMSProtocolError("Incomplete handshake data")

    @staticmethod
    async def _compress_data(data: bytes, flag: ConnectionFlag = ConnectionFlag.Lz4) -> bytes:
        if flag == ConnectionFlag.NoZip:
            return data
        else:
            loop = asyncio.get_event_loop()
            if flag == ConnectionFlag.Lz4:
                data = await loop.run_in_executor(None, lz4.compress, data)
            elif flag == ConnectionFlag.Gzip:
                data = await loop.run_in_executor(None, gzip.compress, data)
            return data

    @staticmethod
    async def _decompress_data(data: bytes, flag: ConnectionFlag = ConnectionFlag.Lz4) -> bytes:
        if flag == ConnectionFlag.NoZip:
            return data
        else:
            loop = asyncio.get_event_loop()
            if flag == ConnectionFlag.Lz4:
                data = await loop.run_in_executor(None, lz4.decompress, data)
            elif flag == ConnectionFlag.Gzip:
                data = await loop.run_in_executor(None, gzip.decompress, data)
            return data
