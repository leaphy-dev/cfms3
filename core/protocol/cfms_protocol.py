import asyncio
import json
import os
from dataclasses import dataclass
from datetime import time
from typing import Dict, Any

from core.protocol.base_protocol import CFMSBaseProtocol, CFMSProtocolError, ConnectionFlag, CFMCBaseConnection
from utils.crypto import CryptoContext


@dataclass()
class CfmsComConnection(CFMCBaseConnection):
    """
    Connection instance of cfms server.
    """
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    crypto: CryptoContext | None = None

    async def close(self):
        self.writer.close()
        await self.writer.wait_closed()

    def get_extra_info(self, name: str, default: Any | None = None):
        self.writer.get_extra_info(name, default)


class CFMSProtocol(CFMSBaseProtocol):
    """
    CFMS命令协议处理器
    5字节头部：
    |4字节帧长度|1字节标识|
    """

    async def read(self, conn: CfmsComConnection) -> bytes:
        """
        从流中读取完整数据帧
        :return: bytes
        :raises ProtocolError: 协议违反时抛出
        """
        data_length = 0
        try:
            # 读取5字节头部
            header = await conn.reader.readexactly(5)
        except asyncio.IncompleteReadError as e:
            if not e.partial:
                return b""  # 正常关闭连接
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
                return b""

                # 读取数据体
            data = await conn.reader.readexactly(data_length)
            decrypted_data = conn.crypto.decrypt(data)

            decompressed_data = await self._decompress_data(decrypted_data, compression_flag)

            self.logger.debug(
                f"接收到{len(data) + 5}字节数据， 解密解压后{len(decompressed_data)}字节，是使用{compression_flag}压缩的")

            return decompressed_data

        except asyncio.IncompleteReadError as e:
            raise CFMSProtocolError(f"数据体不完整，预期 {data_length} 字节") from e

    async def write(self, data: bytes, conn: CfmsComConnection) -> bool:
        """
        写入完整数据帧到流，先压缩再加密
        :param data: 一个消息字典
        :param conn:
        """
        try:
            compressed_data = await self._compress_data(data, self.compression_flag) # 压缩
            encrypted_data = conn.crypto.encrypt(compressed_data) # 加密
            # 构建帧头部
            header = len(encrypted_data).to_bytes(4, byteorder='big') + bytes([self.compression_flag.value])
            # 完整帧数据
            frame = header + encrypted_data
            # 发送数据
            conn.writer.write(frame)
            await conn.writer.drain()

            self.logger.debug(f"发送{len(frame)}字节数据，使用{self.compression_flag}压缩")
            return True
        except Exception as e:
            self.logger.debug(f"An error occurred when sending datum{e}")
            return False

    async def recv_command(self, conn: CfmsComConnection) -> Dict:
        try:
            return json.loads((await self.read(conn)).decode())
        except json.JSONDecodeError:
            self.logger.debug("Invalid json data.")
            return {}

    async def send_command(self, command: Dict, conn: CfmsComConnection):
        return await self.write(json.dumps(command).encode(), conn)

    async def send_stream(self, reader: asyncio.StreamReader,
                          file_size: int, conn: CfmsComConnection,
                          chunk_size: int = 8192) -> bool:
        """
        通过文件StreamReader发送文件
        :param reader: 文件StreamReader
        :param file_size: 文件大小
        :param conn: 网络连接
        :param chunk_size: 分块大小
        :return: 是否成功
        """
        try:
            sent_size = 0
            while sent_size < file_size:
                # 计算本次读取的大小
                read_size = min(chunk_size, file_size - sent_size)

                # 从文件流读取数据
                chunk = await reader.read(read_size)
                if not chunk:
                    break

                # 使用现有的write方法发送数据块
                success = await self.write(chunk, conn)
                if not success:
                    self.logger.error("发送文件块失败")
                    return False

                sent_size += len(chunk)
                self.logger.debug(f"已发送 {sent_size}/{file_size} 字节")

            self.logger.debug(f"文件流发送完成: {sent_size} 字节")
            return sent_size == file_size

        except Exception as e:
            self.logger.error(f"发送文件流时发生错误: {e}")
            return False

    async def receive_stream(self, file_writer: asyncio.StreamWriter,
                             conn: CfmsComConnection,
                             expected_size: int = None) -> bool:
        """
        接收文件并写入到文件StreamWriter
        :param file_writer: 文件StreamWriter
        :param conn: 网络连接
        :param expected_size: 预期文件大小（可选）
        :return: 是否成功
        """
        try:
            received_size = 0
            while True:
                # 使用现有的read方法读取数据块
                chunk = await self.read(conn)
                if not chunk:
                    break

                # 写入到文件流
                file_writer.write(chunk)
                await file_writer.drain()

                received_size += len(chunk)

                # 如果知道预期大小，检查是否接收完成
                if expected_size and received_size >= expected_size:
                    break

                self.logger.debug(f"已接收 {received_size} 字节")

            self.logger.debug(f"文件流接收完成: {received_size} 字节")
            return True

        except Exception as e:
            self.logger.error(f"接收文件流时发生错误: {e}")
            return False