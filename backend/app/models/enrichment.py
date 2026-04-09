import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models import Base


class Enrichment(Base):
    __tablename__ = "enrichments"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False
    )
    host: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    data: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    queries_run: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    queries_failed: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        nullable=False, server_default=func.now()
    )

    alert: Mapped["Alert"] = relationship(back_populates="enrichments")  # noqa: F821

    def __repr__(self) -> str:
        return f"<Enrichment {self.id} alert={self.alert_id} host={self.host}>"
