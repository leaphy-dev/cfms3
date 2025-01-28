import asyncio
import logging

from tortoise import Tortoise

from config import SQLITE_TEMPLATE
from core.auth.auth_service import AuthService
from core.database.models import User
from core.exception import *
from core.protocol.command_protocol import CFMSProtocol, ConnectionFlag, CfmsComConnection
from core.server_cmd import CFMSTerminal


class CfmsServer:
    def __init__(self,
                 host='0.0.0.0',
                 port=8888,
                 logger=logging.getLogger(f"CFMSServer"),
                 use_terminal: bool = True):
        self.logger = logger
        self._main_loop: asyncio.AbstractEventLoop = asyncio.get_event_loop()
        self._server_task = None
        self._use_terminal: bool = use_terminal
        self._terminal: CFMSTerminal | None = None
        self.auth_service = AuthService()
        self.host = host
        self.port = port
        self.protocol = CFMSProtocol(max_frame_size=5 * 1024 * 1024,
                                     compression_flag=ConnectionFlag.Lz4,
                                     logger=self.logger)  # 5MB限制
        self._stop_flag = asyncio.Event()
        self.active_tasks = set()
        # 配置日志处理器
        self.logger = logging.getLogger("CFMSServer")

    async def _send_error(self, writer, exc: AppException):
        """统一错误响应方法"""
        response = {
            "status": "error",
            "code": exc.code,
            "message": exc.message
        }
        await self.protocol.write(response, writer)

    async def init_db(self):
        self.logger.info("正在连接数据库...")
        await Tortoise.init(config=SQLITE_TEMPLATE)
        await Tortoise.generate_schemas()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """处理每个客户端连接"""
        try:
            conn = CfmsComConnection(writer=writer, reader=reader)
            # 握手
            await self.protocol.server_side_shake_hand(conn)
            self.logger.info(f"来自{writer.get_extra_info(name="peername")}的连接")
            # 用户认证
            # 接收加密的认证信息
            auth_data = await self.protocol.read(conn)
            username, password = auth_data["username"], auth_data["password"]
            # 数据库验证
            user = await User.objects.get_by_username(username=username)  # type: ignore
            if not user or not await user.verify_password(password):
                await self._send_error(writer, AuthenticationError("认证失败"))
                self.logger.info(f"User: {username} fall to login.{writer.get_extra_info(name="peername")}")
                return
            self.logger.info(f"User: {username} login successfully.{writer.get_extra_info(name="peername")}")

            # 生成令牌
            token = self.auth_service.generate_token(user.id, 1)  # <--- 令牌在此生成
            await self.protocol.write({"token": token}, conn)

            # 创建子协程
            task = self._main_loop.create_task(self.handel_request(token, conn))
            self.active_tasks.add(task)
            task.add_done_callback(self.active_tasks.discard)

        except Exception as e:
            # 在分配到子协程处理前任何异常都会关闭连接
            self.logger.error(f"客户端处理异常: {e}")
            writer.close()
            await writer.wait_closed()
            raise e

    async def handel_request(self, token, conn):
        # 实现文件操作和权限验证逻辑
        try:
            while True:
                data = await self.protocol.read(conn)
                self.logger.debug(f"received message:{data}")
                if not data:
                    self.logger.info(f"{conn.writer.get_extra_info(name="peername")}断开了连接")
                    break
                try:
                    token = await self.auth_service.verify_token(data["token"])
                except Exception as e:
                    self.logger.error(f"令牌错误{e}")
                if token:
                    print(data)
                else:
                    break
        finally:
            conn.close()

    async def start(self):
        if self._use_terminal:
            self._terminal = CFMSTerminal(logger=self.logger, loop=self._main_loop, parent=self)
            await self._terminal.start_interface()
        try:
            self.logger.info("正在启动CFMS服务器...")
            await self.init_db()
            await self.auth_service.init_keys()
            self.logger.info("OK")
            self._server_task = self._main_loop.create_task(self._server_forever())
            await asyncio.wait([self._server_task])  # 等待关闭事件触发
        finally:
            # 显式关闭服务器并等待资源释放
            if self._stop_flag.is_set():
                return
            await self.shutdown()

    async def _server_forever(self):
        """替代直接调用server_forever()的可取消任务"""
        try:
            _server = await asyncio.start_server(self.handle_client, self.host, self.port)
            async with _server:
                await _server.serve_forever()
        except OSError as e:
            if e.errno == 10048:
                self.logger.error(e.strerror)

    async def shutdown(self):
        self._stop_flag.set()
        self.logger.info("正在关闭服务器...")
        if not self._server_task.cancelled():
            self._server_task.cancel()

        tasks = [t for t in self.active_tasks if t is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
        self.logger.info(f"强制关闭了{len(self.active_tasks)}个客户端连接。")
        self.logger.info("正在关闭数据库连接...")
        await Tortoise.close_connections()
        if self._use_terminal:
            await self._terminal.stop_interface()
        for task in asyncio.all_tasks():
            task.cancel()
