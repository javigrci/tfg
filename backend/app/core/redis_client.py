"""Cliente Redis para uso directo desde la app (contador de re-entregas de
`app/tasks.py`), aparte del que usa Celery."""
import redis

from app.core.config import get_settings


def get_redis() -> redis.Redis:
    return redis.Redis.from_url(get_settings().redis_url, decode_responses=True)
