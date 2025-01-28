import asyncio
from typing import Tuple

import bcrypt


def hash_password(password: str) -> Tuple[str, str]:
    """生成带盐值的密码哈希"""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8'), salt.decode('utf-8')


def verify_password(
        stored_hash: str,
        input_password: str
) -> bool:
    """验证密码是否匹配"""
    try:
        return bcrypt.checkpw(
            input_password.encode('utf-8'),
            stored_hash.encode('utf-8')
        )
    except ValueError:
        return False


async def async_verify_password(
        stored_hash: str,
        input_password: str
) -> bool:
    """异步验证密码（避免阻塞事件循环）"""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        verify_password,
        stored_hash,
        input_password
    )
