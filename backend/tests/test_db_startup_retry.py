"""Retry de conexión a la BD en el arranque (`app/main.py`, lifespan).

`docker compose up` completo espera `db: condition: service_healthy` (ver
`docker-compose.yml`), pero `make dev` levanta `db` y `uvicorn` casi a la vez, sin esa
garantía — Postgres puede seguir inicializando cuando `create_all` intenta conectar.
Antes, un arranque en frío lento hacía caer el backend con `OperationalError` en el
primer intento.
"""
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.exc import OperationalError

from app.main import _DB_STARTUP_RETRIES, _wait_for_database


def _op_error() -> OperationalError:
    return OperationalError("SELECT 1", {}, Exception("connection refused"))


def test_conecta_a_la_primera_no_reintenta():
    with patch("app.main.engine") as mock_engine, patch("app.main.time.sleep") as mock_sleep:
        mock_engine.connect.return_value.__enter__ = MagicMock(return_value=None)
        mock_engine.connect.return_value.__exit__ = MagicMock(return_value=False)
        _wait_for_database()
        assert mock_engine.connect.call_count == 1
        mock_sleep.assert_not_called()


def test_reintenta_hasta_que_la_bd_responde():
    with patch("app.main.engine") as mock_engine, patch("app.main.time.sleep") as mock_sleep:
        ok_cm = MagicMock()
        ok_cm.__enter__ = MagicMock(return_value=None)
        ok_cm.__exit__ = MagicMock(return_value=False)
        # Falla 2 veces (BD todavía arrancando), a la 3ª conecta.
        mock_engine.connect.side_effect = [_op_error(), _op_error(), ok_cm]

        _wait_for_database()

        assert mock_engine.connect.call_count == 3
        assert mock_sleep.call_count == 2


def test_agota_reintentos_y_lanza_runtime_error():
    with patch("app.main.engine") as mock_engine, patch("app.main.time.sleep"):
        mock_engine.connect.side_effect = _op_error()

        with pytest.raises(RuntimeError, match="No se pudo conectar"):
            _wait_for_database()

        assert mock_engine.connect.call_count == _DB_STARTUP_RETRIES
