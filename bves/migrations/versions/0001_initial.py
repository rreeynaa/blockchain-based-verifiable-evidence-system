"""initial schema

Revision ID: 0001
Revises:
"""
import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("password_hash", sa.String(256), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
    )
    op.create_index("ix_users_username", "users", ["username"], unique=True)

    op.create_table(
        "batches",
        sa.Column("batch_id", sa.Integer, primary_key=True, autoincrement=False),
        sa.Column("case_id", sa.String(64), nullable=False),
        sa.Column("merkle_root", sa.String(64), nullable=False),
        sa.Column("tx_hash", sa.String(66), nullable=False),
        sa.Column("block_number", sa.Integer, nullable=False),
        sa.Column("timestamp", sa.Integer, nullable=False),
        sa.Column("submitter", sa.String(64), nullable=False),
        sa.Column("file_count", sa.Integer, nullable=False),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_batches_case_id", "batches", ["case_id"])
    op.create_index("ix_batches_merkle_root", "batches", ["merkle_root"])

    op.create_table(
        "files",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("batch_id", sa.Integer, sa.ForeignKey("batches.batch_id"), nullable=False),
        sa.Column("file_index", sa.Integer, nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("size", sa.Integer, nullable=False),
        sa.Column("file_hash", sa.String(64), nullable=False),
        sa.Column("cid", sa.String(128), nullable=False),
        sa.UniqueConstraint("batch_id", "file_index"),
    )
    for col in ("batch_id", "filename", "file_hash", "cid"):
        op.create_index(f"ix_files_{col}", "files", [col])

    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(64), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("batch_id", sa.Integer, nullable=True),
        sa.Column("tx_hash", sa.String(66), nullable=True),
        sa.Column("result", sa.String(16), nullable=True),
        sa.Column("detail", sa.Text, nullable=False),
    )
    op.create_index("ix_audit_log_ts", "audit_log", ["ts"])
    op.create_index("ix_audit_log_action", "audit_log", ["action"])


def downgrade() -> None:
    op.drop_table("audit_log")
    op.drop_table("files")
    op.drop_table("batches")
    op.drop_table("users")
