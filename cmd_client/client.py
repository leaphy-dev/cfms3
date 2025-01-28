import asyncio
import logging

from core.protocol.command_protocol import CFMSProtocol, ConnectionFlag, CfmsComConnection
from utils.crypto import CryptoContext  # 假设与服务器使用相同的加密模块


class TestClient:
    def __init__(self, host='127.0.0.1', port=8888):
        self.conn: CfmsComConnection = CfmsComConnection()
        self.encrypted_token = None
        self.host = host
        self.port = port
        self.crypto = CryptoContext()
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger("TestClient")
        self.protocol = CFMSProtocol(compression_flag=ConnectionFlag.Gzip)

    async def connect(self):
        """建立连接并完成认证流程"""
        reader, writer = await asyncio.open_connection(self.host, self.port)
        conn = CfmsComConnection(reader=reader, writer=writer)
        self.conn = conn
        # 接收服务器公钥
        await self.protocol.client_side_shake_hand(conn)

        # ========== 用户认证 ==========
        # 发送测试凭证（根据服务器配置修改）
        await self.protocol.write({"username": "admin", "password": "123456"}, conn)

        # 接收令牌
        recv_token = await self.protocol.read(conn)
        self.encrypted_token = recv_token["token"]
        self.logger.info(f"认证成功，令牌: {self.encrypted_token}...")

    async def receive_messages(self):
        """持续接收并打印服务器消息"""
        try:
            while True:
                data = await self.protocol.read(self.conn)
                if data is None:
                    break  # 明确处理空数据
                self.logger.info(data)

        except asyncio.IncompleteReadError:
            self.logger.warning("连接已关闭")
        except Exception as e:
            self.logger.error(f"接收错误: {e}")

    async def send_commands(self):
        """发送测试命令的交互式控制台"""
        while True:
            try:
                # 读取用户输入
                cmd = await asyncio.get_event_loop().run_in_executor(
                    None, input, "输入命令 (q退出) > ")

                if cmd.lower() == 'q':
                    await self.conn.close()
                    break

                await self.protocol.write({"request": cmd, "token": self.encrypted_token}, self.conn)

            except Exception as e:
                self.logger.error(f"发送失败: {str(e)}")
                break

    async def run(self):
        """运行客户端"""
        await self.connect()
        # 创建并行任务
        receiver = asyncio.create_task(self.receive_messages())
        sender = asyncio.create_task(self.send_commands())

        await asyncio.gather(receiver, sender)

        if self.conn:
            await self.conn.close()


if __name__ == '__main__':
    client = TestClient()
    asyncio.run(client.run())
