import asyncio
from enum import Enum
from typing import AsyncGenerator, AsyncIterator, Optional

from core.protocol.base_protocol import CFMSProtocolError, ConnectionFlag, CFMSBaseProtocol
from utils.crypto import CryptoContext


class CFMCDataConnection:
    """连接基础类"""

    def __init__(self):
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.crypto: Optional[CryptoContext] = None
        self.is_paused: bool = False


class ControlCommand(bytes, Enum):
    """控制指令枚举"""
    Pause = b'PAUSE'
    Resume = b'RESUME'


class CFMSStreamProtocol(CFMSBaseProtocol):
    """流式传输协议实现
    5字节头部：
    和命令协议相同
    """

    async def send_frame(
            self,
            conn: CFMCDataConnection,
            data: bytes,
            is_end: bool = False,
            heartbeat: bool = False,
            timeout: float = 30.0
    ) -> None:
        """发送数据帧"""
        try:
            if heartbeat:
                header = bytes([ConnectionFlag.Heartbeat.value]) + b'\x00' * 4
                conn.writer.write(header)
                await asyncio.wait_for(conn.writer.drain(), timeout=timeout)
                return

            if is_end:
                compressed_data = await self._compress_data(b'', ConnectionFlag.NoZip)
            else:
                compressed_data = await self._compress_data(data, self.compression_flag)

            encrypted_data = conn.crypto.encrypt(compressed_data)
            header = len(encrypted_data).to_bytes(4, 'big')
            header += bytes([self.compression_flag.value if not is_end else ConnectionFlag.NoZip.value])

            conn.writer.write(header + encrypted_data)
            await asyncio.wait_for(conn.writer.drain(), timeout=timeout)

        except (asyncio.TimeoutError, ConnectionError) as e:
            self.logger.error(f"Send frame failed: {str(e)}")
            conn.writer.close()
            await conn.writer.wait_closed()
            raise CFMSProtocolError("Connection error during send")

    async def receive_frame(self, conn: CFMCDataConnection, timeout: float = 60.0) -> bytes:
        """接收数据帧"""
        try:
            header = await asyncio.wait_for(conn.reader.readexactly(5), timeout=timeout)
        except asyncio.TimeoutError:
            self.logger.warning("Receive frame timeout")
            conn.writer.close()
            raise CFMSProtocolError("Receive timeout")
        except asyncio.IncompleteReadError:
            return b''

        try:
            flag = ConnectionFlag(header[4])
        except ValueError:
            raise CFMSProtocolError(f"Invalid compression flag: {header[0]}")

        data_length = int.from_bytes(header[0:4], 'big')

        if flag == ConnectionFlag.Heartbeat:
            return b''

        if flag == ConnectionFlag.Control:
            cmd_data = await conn.reader.readexactly(data_length)
            cmd = ControlCommand(cmd_data)
            if cmd == ControlCommand.Pause:
                conn.is_paused = True
                self.logger.info("Download paused")
            elif cmd == ControlCommand.Resume:
                conn.is_paused = False
                self.logger.info("Download resumed")
            return b''

        if data_length > self.max_frame_size:
            raise CFMSProtocolError(f"Frame size {data_length} exceeds limit")

        encrypted_data = await conn.reader.readexactly(data_length)
        compressed_data = conn.crypto.decrypt(encrypted_data)

        if flag == ConnectionFlag.NoZip and compressed_data == b'':
            return b''

        return await self._decompress_data(compressed_data, flag)

    @staticmethod
    async def send_control(conn: CFMCDataConnection, cmd: ControlCommand):
        """发送控制指令"""
        header = bytes([ConnectionFlag.Control.value]) + len(cmd.value).to_bytes(4, 'big')
        conn.writer.write(header + cmd.value)
        await conn.writer.drain()

    async def start_heartbeat(self, conn: CFMCDataConnection, interval: int = 30):
        """启动心跳任务"""
        while True:
            if conn.writer.is_closing():
                break
            try:
                await self.send_frame(conn, b'', heartbeat=True)
                await asyncio.sleep(interval)
            except CFMSProtocolError:
                break

    async def send_stream(self, conn: CFMCDataConnection, stream: AsyncIterator[bytes]):
        """流式发送"""
        async for chunk in stream:
            while conn.is_paused:
                await asyncio.sleep(0.5)
            await self.send_frame(conn, chunk)
        await self.send_frame(conn, b'', is_end=True)

    async def receive_stream(self, conn: CFMCDataConnection) -> AsyncGenerator[bytes, None]:
        """流式接收"""
        while True:
            chunk = await self.receive_frame(conn)
            if not chunk:
                break
            yield chunk
