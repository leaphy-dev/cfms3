import asyncio
import logging
import sys

from core.server import CfmsServer

# 仅在非Windows系统启用uvloop
if sys.platform != "win32":
    try:
        import uvloop  # type:ignore
    except ImportError:
        pass  # 如果未安装uvloop则使用默认循环
else:
    uvloop = None  # Windows下不加载uvloop


async def main():
    logger = logging.getLogger("CFMSServer")
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    # 配置事件循环
    if uvloop is not None:
        uvloop.install()  # type:ignore
        logger.info("✅ 已启用uvloop加速")
    else:
        logger.info("⚠️ Windows系统不支持uvloop加速")

    # 启动文件服务器
    server = CfmsServer(logger=logger, use_terminal=False)
    await server.start()


if __name__ == "__main__":
    # 兼容Windows的事件循环策略
    try:
        asyncio.run(main())
    except asyncio.CancelledError:
        exit()
    except Exception as e:
        raise e
