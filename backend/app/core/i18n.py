"""Textos fijos del informe PDF, por idioma (spec 006).

Mismo patrón "i18n = JSON estático" que el frontend. El texto de dominio (títulos de
hallazgo, comandos, evidencias) NO pasa por aquí — solo el texto de plantilla.
"""
import json
from functools import lru_cache
from pathlib import Path

_I18N_DIR = Path(__file__).parent.parent / "i18n"
_DEFAULT = "en"


@lru_cache(maxsize=8)
def _load(lang: str) -> dict:
    path = _I18N_DIR / f"report.{lang}.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


class _Strings(dict):
    """Dict con fallback al idioma por defecto para claves ausentes."""

    def __init__(self, lang: str):
        super().__init__(_load(lang))
        self._fallback = _load(_DEFAULT) if lang != _DEFAULT else {}

    def __missing__(self, key: str) -> str:
        return self._fallback.get(key, key)


@lru_cache(maxsize=8)
def report_strings(lang: str) -> _Strings:
    if lang not in ("es", "en"):
        lang = _DEFAULT
    return _Strings(lang)
