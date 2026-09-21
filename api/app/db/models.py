"""
SQLAlchemy models for GraphRisk's relational (PostgreSQL) layer.

Neo4j holds the graph (assets, risks, controls, frameworks, vulnerabilities).
PostgreSQL holds everything that is inherently relational and tenant-scoped
administrative data: who can log in, which tenant they belong to, and an
audit trail of what they did. This split mirrors the architecture described
in the original Part 2 technical blueprint.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import String, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def _uuid() -> str:
    return str(uuid.uuid4())


class Tenant(Base):
    __tablename__ = "tenants"

    id:         Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    name:       Mapped[str] = mapped_column(String(200), nullable=False)
    graph_tenant_id: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    # ^ the tenant_id string used inside Neo4j node properties (e.g. "demo") --
    #   kept separate from the Postgres UUID primary key so existing graph
    #   data (tenant_id: "demo") does not need to be rewritten.
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                  default=lambda: datetime.now(timezone.utc))

    users: Mapped[list["User"]] = relationship(back_populates="tenant")


class User(Base):
    __tablename__ = "users"

    id:              Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    tenant_id:       Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("tenants.id"), nullable=False)
    email:           Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role:            Mapped[str] = mapped_column(String(50), nullable=False, default="member")
    # roles: "owner" | "admin" | "member" -- kept simple; expand later if needed
    created_at:      Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                        default=lambda: datetime.now(timezone.utc))

    tenant: Mapped["Tenant"] = relationship(back_populates="users")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id:         Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    tenant_id:  Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("tenants.id"), nullable=False)
    user_id:    Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=True)
    action:     Mapped[str] = mapped_column(String(100), nullable=False)   # e.g. "control.status_updated"
    resource:   Mapped[str] = mapped_column(String(255), nullable=True)    # e.g. a control id
    detail:     Mapped[str] = mapped_column(Text, nullable=True)
    timestamp:  Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                  default=lambda: datetime.now(timezone.utc))


class ReportSnapshot(Base):
    __tablename__ = "report_snapshots"

    id:            Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    tenant_id:     Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("tenants.id"), nullable=False)
    snapshot_data: Mapped[str] = mapped_column(Text, nullable=False)  # JSON-serialized dashboard/report state
    created_at:    Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                      default=lambda: datetime.now(timezone.utc))
