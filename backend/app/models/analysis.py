import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models import Base


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False
    )

    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    hypothesis: Mapped[str] = mapped_column(Text, nullable=False, default="")
    possible_causes: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    key_indicators: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    recommended_checks: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    confidence_note: Mapped[str] = mapped_column(Text, nullable=False, default="")

    raw_response: Mapped[str] = mapped_column(Text, nullable=False, default="")
    model_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    prompt_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    completion_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    processing_time_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_at: Mapped[datetime] = mapped_column(
        nullable=False, server_default=func.now()
    )

    alert: Mapped["Alert"] = relationship(back_populates="analyses")  # noqa: F821

    def __repr__(self) -> str:
        return f"<Analysis {self.id} alert={self.alert_id}>"
