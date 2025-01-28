# SQLite配置
SQLITE_TEMPLATE = {
    'connections': {
        'default': 'sqlite://storage/db.sqlite3'
    },
    'apps': {
        'models': {
            'models': ['core.database.models'],
        }
    },
    "log_level": "WARNING"
}

# MySQL配置
MYSQL_TEMPLATE = {
    'connections': {
        'default': {
            'engine': 'tortoise.backends.mysql',
            'credentials': {
                'host': 'localhost',
                'user': 'root',
                'password': 'password',
                'database': 'fileserver',
            }
        }
    },
    'apps': {
        'models': {
            'models': ['models'],
            'default_connection': 'default',
        }
    }
}
