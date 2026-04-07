import enum
import uuid
from datetime import datetime

from sqlalchemy import Enum, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models import Base


class AlertStatus(enum.StrEnum):
    PENDING = "pending"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    wazuh_id: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True)

    raw_data: Mapped[dict] = mapped_column(JSONB, nullable=False)
    normalized_data: Mapped[dict] = mapped_column(JSONB, nullable=False)

    severity: Mapped[str] = mapped_column(String(50), nullable=False, default="unknown")
    rule_id: Mapped[str] = mapped_column(String(50), nullable=False, default="")
    rule_description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    agent_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")

    status: Mapped[AlertStatus] = mapped_column(
        Enum(AlertStatus, name="alert_status", native_enum=False),
        nullable=False,
        default=AlertStatus.PENDING,
    )

    created_at: Mapped[datetime] = mapped_column(
        nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        nullable=False, server_default=func.now(), onupdate=func.now()
    )

    analyses: Mapped[list["Analysis"]] = relationship(  # noqa: F821
        back_populates="alert", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Alert {self.id} rule={self.rule_id} status={self.status}>"
