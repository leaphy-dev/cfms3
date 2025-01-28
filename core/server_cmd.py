import asyncio
import logging
import platform
import shutil
import sys
from abc import ABC, abstractmethod
from asyncio import AbstractEventLoop
from collections import deque, UserList
from logging import Handler

from aioconsole import ainput

from core.database.models import User


class AsyncLogHandler(Handler):
    def __init__(self, queue):
        super().__init__()
        self.queue = queue

    def emit(self, record):
        msg = self.format(record)
        self.queue.put_nowait(msg)


class TerminalInterface(ABC):
    """分屏终端界面"""

    def __init__(self,
                 logger: logging.Logger = None,
                 loop: AbstractEventLoop = None
                 ):
        self.log_queue = asyncio.Queue()
        self.logger = logger or logging.getLogger()
        self.loop = loop or asyncio.get_event_loop()
        self.logger.handlers = []
        handler = AsyncLogHandler(self.log_queue)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        self._stop_flag = asyncio.Event()

        # Windows平台ANSI支持
        if platform.system() == "Windows":
            from ctypes import windll
            kernel32 = windll.kernel32
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            kernel32.SetConsoleMode(handle, 7)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING

        self.ui_tasks = set()
        self.active_command_task = set()
        self.log_buffer = deque(maxlen=100)

        self.command_history = deque(maxlen=50)

    async def start_interface(self):
        """启动界面协程"""
        self.ui_tasks.update({
            self.loop.create_task(self._update_logs()),
            self.loop.create_task(self._refresh_screen()),
            self.loop.create_task(self._handle_input())
        })

    async def stop_interface(self):
        """停止界面协程"""
        self._stop_flag.set()
        for task in self.active_command_task:
            task.cancel()

        for task in self.ui_tasks:
            task.cancel()
        # await asyncio.gather(*self._ui_tasks, return_exceptions=True) # 递归bug

    async def _update_logs(self):
        """持续更新日志缓冲区"""
        while True:
            log = await self.log_queue.get()
            self.log_buffer.append(log)

    def _render_interface(self):
        """PowerShell专用渲染方法"""
        cols, rows = shutil.get_terminal_size()

        show_command_history_num = 10

        display_lines = rows - show_command_history_num - 1

        # 构建双重清屏缓冲区
        buffer = [
            "\033[2J\033[3J",  # 增强清屏指令
            "\033[1;1H",  # 光标定位到左上角

        ]

        # 动态填充日志行+空白覆盖
        visible_logs = list(self.log_buffer)[-display_lines:]
        for i in range(1, display_lines + 1):
            line_content = visible_logs[i - 1] + "\n" if i <= len(visible_logs) else ""
            buffer.append(f"\033[{i};1H\033[K{line_content}")

        buffer.append(f"\033[{display_lines};1H")
        buffer.append("─" * cols + "\n")

        # 固定输入行（兼容PS滚动特性）

        command_history = list(self.command_history)[-10:]
        for i in range(1, show_command_history_num + 1):
            line_content = command_history[i - 1] + "\n" if i <= len(command_history) else ""
            buffer.append(f"\033[{display_lines + i};1H\033[K{line_content}")
        buffer.append(f"\033[{rows};1H")
        buffer.append("\033[K> ")

        sys.stdout.write("".join(buffer))
        sys.stdout.flush()

    async def _refresh_screen(self):
        """智能刷新策略，减少不必要的重绘"""
        last_log_count = 0
        last_term_size = (0, 0)

        while True:
            await asyncio.sleep(0.1)

            current_size = shutil.get_terminal_size()
            current_log_count = len(self.log_buffer)

            # 仅在以下情况重绘：
            #             # 1. 终端尺寸变化
            #             # 2. 有新日志到达
            if (current_size != last_term_size or
                    current_log_count != last_log_count):
                self._render_interface()
                last_term_size = current_size
                last_log_count = current_log_count

    async def _handle_input(self):
        """处理用户输入指令"""
        while True:
            try:
                cmd = await ainput()
                if cmd:
                    self.command_history.append(cmd)
                    process_command_task = self.loop.create_task(self.process_command(cmd.strip().lower()))
                    self.active_command_task.add(process_command_task)
                    process_command_task.add_done_callback(self.active_command_task.discard)
            except (EOFError, KeyboardInterrupt):
                return
            except Exception as e:
                if self._stop_flag.is_set():
                    return
                self.logger.error(f"命令处理错误: {str(e)}")
            finally:
                self._render_interface()

    @abstractmethod
    async def process_command(self, command: str):
        raise NotImplementedError

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.stop_interface()


class CommandArgumentList(UserList):
    def __getitem__(self, item):
        try:
            obj = self.data[item]
            try:
                obj = float(obj)
                return obj
            except ValueError:
                return obj
        except IndexError:
            return None


class CFMSTerminal(TerminalInterface):
    def __init__(self, logger, loop, parent):
        super().__init__(logger, loop)
        self.server = parent

        logo = \
            r"""
      ___           ___           ___           ___              
     /\  \         /\  \         /\__\         /\  \             
    /::\  \       /::\  \       /::|  |       /::\  \            
   /:/\:\  \     /:/\:\  \     /:|:|  |      /:/\ \  \           
  /:/  \:\  \   /::\~\:\  \   /:/|:|__|__   _\:\~\ \  \          
 /:/__/ \:\__\ /:/\:\ \:\__\ /:/ |::::\__\ /\ \:\ \ \__\         
 \:\  \  \/__/ \/__\:\ \/__/ \/__/~~/:/  / \:\ \:\ \/__/         
  \:\  \            \:\__\         /:/  /   \:\ \:\__\           
   \:\  \            \/__/        /:/  /     \:\/:/  /           
    \:\__\                       /:/  /       \::/  /            
     \/__/                       \/__/         \/__/             
"""

        for line in logo.split("\n"):
            self.logger.info(line)

    async def process_command(self, command_line: str):
        command_line = command_line.split()
        try:
            command = command_line.pop(0).lower()
        except IndexError:
            return
        args = CommandArgumentList(command_line)
        try:
            match command:
                case "stop":
                    if args[0] == "-t" and args[1]:
                        for t in range(int(args[1])):
                            self.logger.info(f"{int(args[1]) - t}s后关闭服务器")
                            await asyncio.sleep(1)
                    await self.server.shutdown()
                case "user":
                    match args[0]:
                        case "list":
                            users = await User.all()
                            self.logger.info(f"total:{len(users)}")
                            for u in users:
                                self.logger.info(u.username)
                        case "delete":
                            await User.objects.delete_user(args[1])
                        case "create":
                            await User.objects.create_user(args[1], args[2])
                case _:
                    self.logger.warning(f"Unknown command: '{command}'")
        except Exception as e:
            self.logger.error(e)
