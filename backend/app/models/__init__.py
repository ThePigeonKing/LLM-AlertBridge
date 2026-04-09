from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


from backend.app.models.alert import Alert  # noqa: E402, F401
from backend.app.models.analysis import Analysis  # noqa: E402, F401
from backend.app.models.enrichment import Enrichment  # noqa: E402, F401
