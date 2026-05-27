import platform
import socket
import subprocess
from urllib.parse import urlparse
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.domain.enums import TargetStatus
from app.models.entities import Audit, Target
from app.schemas.audit import TargetCreate, TargetUpdate


def _check_reachability(address: str) -> TargetStatus:
    """
    Comprueba si el target es accesible.

    - Si la dirección incluye un puerto (host:port) o es una URL (http://...), intenta
      una conexión TCP al puerto indicado.
    - Si solo es una IP o hostname sin puerto, lanza un ping.
    """
    try:
        parsed = urlparse(address)
        if parsed.scheme in ("http", "https") and parsed.hostname:
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        elif ":" in address:
            parts = address.rsplit(":", 1)
            host = parts[0]
            port = int(parts[1])
        else:
            host = address
            port = None

        if port is not None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((host, port))
            sock.close()
            return TargetStatus.REACHABLE if result == 0 else TargetStatus.UNREACHABLE

        param = "-n" if platform.system().lower() == "windows" else "-c"
        outcome = subprocess.run(
            ["ping", param, "1", address],
            capture_output=True,
            timeout=5,
        )
        return TargetStatus.REACHABLE if outcome.returncode == 0 else TargetStatus.UNREACHABLE

    except Exception:
        return TargetStatus.UNREACHABLE


class TargetService:
    def __init__(self, db: Session):
        self.db = db

    def list_targets(self) -> list[Target]:
        return list(self.db.scalars(select(Target).order_by(Target.created_at.desc())).all())

    def get_target(self, target_id: int) -> Target | None:
        return self.db.scalar(select(Target).where(Target.id == target_id))

    def create_target(self, payload: TargetCreate) -> Target:
        target = Target(
            name=payload.name,
            address=payload.address,
            environment=payload.environment,
            details=payload.details,
            status=_check_reachability(payload.address),
        )
        self.db.add(target)
        self.db.commit()
        self.db.refresh(target)
        return target

    def update_target(self, target: Target, payload: TargetUpdate) -> Target:
        if payload.name is not None:
            target.name = payload.name
        if payload.address is not None:
            target.address = payload.address
            target.status = _check_reachability(payload.address)
        self.db.commit()
        self.db.refresh(target)
        return target

    def check_target(self, target: Target) -> Target:
        """Relanza la comprobación de conectividad y actualiza el estado."""
        target.status = _check_reachability(target.address)
        self.db.commit()
        self.db.refresh(target)
        return target

    def delete_target(self, target: Target) -> None:
        self.db.delete(target)
        self.db.commit()

    def has_audits(self, target_id: int) -> bool:
        return self.db.scalar(
            select(Audit).where(Audit.target_id == target_id)
        ) is not None
