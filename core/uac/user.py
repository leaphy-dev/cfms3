from typing import Optional, TYPE_CHECKING

from tortoise.manager import Manager

from core.auth.password import hash_password

if TYPE_CHECKING:  # 仅类型检查时导入
    from core.database.models import User


class UserManager(Manager):
    async def create_user(self, username: str, password: str) -> "User":
        """创建用户并自动哈希密码"""
        hashed, salt = hash_password(password)
        return await self.create(
            username=username,
            password_hash=hashed,
            salt=salt
        )

    async def delete_user(self, username: str) -> None:
        """删除用户"""
        user = await self.get_by_username(username)
        await user.delete()

    async def get_by_username(self, username: str) -> Optional["User"]:
        """根据用户名获取用户实例"""
        return await self.filter(username=username).first()

    async def authenticate(self, username: str, password: str) -> Optional["User"]:
        """验证用户名和密码，返回用户实例"""
        user = await self.get_by_username(username)
        if user and await user.verify_password(password):
            return user
        return None

    async def get_all_users(self):
        return self.get_queryset().filter()
