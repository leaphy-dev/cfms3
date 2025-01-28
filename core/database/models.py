from tortoise import fields, models

from core.auth.password import async_verify_password
from core.uac.user import UserManager


class User(models.Model):
    id = fields.UUIDField(pk=True)
    username = fields.CharField(max_length=50, unique=True)
    password_hash = fields.CharField(max_length=256)
    salt = fields.CharField(max_length=256)
    token_version = fields.IntField(default=0)  # 令牌版本控制

    objects: UserManager = UserManager()

    async def verify_password(self, password: str) -> bool:
        """验证密码"""
        return await async_verify_password(
            self.password_hash,
            password
        )

    async def rotate_token_version(self):
        """使所有已签发令牌失效"""
        self.token_version += 1
        await self.save()

    def __str__(self):
        return self.username

    def __repr__(self):
        return self.username


class File(models.Model):
    filename = fields.CharField(max_length=255)
    path = fields.CharField(max_length=4096)
    owner = fields.ForeignKeyField('models.User', related_name='files')
    created_at = fields.DatetimeField(auto_now_add=True)


class Permission(models.Model):
    user = fields.ForeignKeyField('models.User', related_name='permissions')
    file = fields.ForeignKeyField('models.File', related_name='permissions')
    can_read = fields.BooleanField(default=False)
    can_write = fields.BooleanField(default=False)
