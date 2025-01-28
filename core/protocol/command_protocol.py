import asyncio
import json
from dataclasses import dataclass
from typing import Dict

from core.protocol.base_protocol import CFMSBaseProtocol, CFMSProtocolError, ConnectionFlag
from utils.crypto import CryptoContext


@dataclass()
class CfmsComConnection(object):
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    crypto: CryptoContext | None = None

    async def close(self):
        self.writer.close()
        await self.writer.wait_closed()


class CFMSProtocol(CFMSBaseProtocol):
    """
    CFMS命令协议处理器
    5字节头部：
    |4字节帧长度|1字节标识|
    """

    async def read(self, conn: CfmsComConnection) -> Dict | None:
        """
        从流中读取完整数据帧
        :return: Dict对象，若连接关闭返回None
        :raises ProtocolError: 协议违反时抛出
        """
        data_length = 0
        try:
            # 读取5字节头部
            header = await conn.reader.readexactly(5)
        except asyncio.IncompleteReadError as e:
            if not e.partial:
                return None  # 正常关闭连接
            raise CFMSProtocolError("不完整的帧头部") from e

        try:
            # 解析帧长度（大端序无符号int）
            data_length = int.from_bytes(header[:4], byteorder='big', signed=False)
            compression_flag = header[4]  # 第5位是压缩标识

            # 长度校验
            if data_length > self.max_frame_size:
                raise CFMSProtocolError(f"数据长度超过限制: {data_length}/{self.max_frame_size}")

            # 压缩标志校验
            try:
                compression_flag = ConnectionFlag(compression_flag)
            except ValueError:
                return

                # 读取数据体
            data = await conn.reader.readexactly(data_length)
            decrypted_data = conn.crypto.decrypt(data)

            decompressed_data = await self._decompress_data(decrypted_data, compression_flag)

            self.logger.debug(
                f"接收到{len(data) + 5}字节数据， 解密解压后{len(decompressed_data)}字节，是使用{compression_flag}压缩的")

            return json.loads(decompressed_data.decode())

        except asyncio.IncompleteReadError as e:
            raise CFMSProtocolError(f"数据体不完整，预期 {data_length} 字节") from e

    async def write(self, data: Dict, conn: CfmsComConnection) -> None:
        """
        写入完整数据帧到流，先加密再压缩
        :param data: 一个消息字典
        :param conn:
        """
        compressed_data = await self._compress_data(json.dumps(data).encode(), self.compression_flag)
        encrypted_data = conn.crypto.encrypt(compressed_data)
        # 构建帧头部
        header = len(encrypted_data).to_bytes(4, byteorder='big') + bytes([self.compression_flag.value])
        # 完整帧数据
        frame = header + encrypted_data
        # 发送数据
        conn.writer.write(frame)
        await conn.writer.drain()

        self.logger.debug(f"发送{len(frame)}字节数据，使用{self.compression_flag}压缩")
