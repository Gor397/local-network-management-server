"""suro owners infrastructure groups incidents and operations"""

from alembic import op
import sqlalchemy as sa

revision = "fae1ac5dc81c"
down_revision = "0003_policy_scopes"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "system_settings",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("value", sa.JSON(), nullable=False),
    )
    op.create_table(
        "ap_groups",
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("template", sa.JSON(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index(
        op.f("ix_ap_groups_created_at"), "ap_groups", ["created_at"], unique=False
    )
    op.create_table(
        "ap_group_members",
        sa.Column("group_id", sa.String(length=36), nullable=False),
        sa.Column("router_id", sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(["group_id"], ["ap_groups.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["router_id"],
            ["routers.id"],
        ),
        sa.PrimaryKeyConstraint("group_id", "router_id"),
    )
    op.create_table(
        "router_telemetry",
        sa.Column("router_id", sa.String(length=36), nullable=False),
        sa.Column("metrics", sa.JSON(), nullable=False),
        sa.Column("clients", sa.JSON(), nullable=False),
        sa.Column("facts", sa.JSON(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["router_id"],
            ["routers.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_router_telemetry_created_at"),
        "router_telemetry",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_router_telemetry_router_id"),
        "router_telemetry",
        ["router_id"],
        unique=False,
    )
    op.create_table(
        "configuration_backups",
        sa.Column("router_id", sa.String(length=36), nullable=False),
        sa.Column("author_id", sa.String(length=36), nullable=True),
        sa.Column("kind", sa.String(length=24), nullable=False),
        sa.Column("encrypted_content", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["author_id"],
            ["administrators.id"],
        ),
        sa.ForeignKeyConstraint(
            ["router_id"],
            ["routers.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_configuration_backups_created_at"),
        "configuration_backups",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_configuration_backups_router_id"),
        "configuration_backups",
        ["router_id"],
        unique=False,
    )
    op.create_table(
        "incidents",
        sa.Column("dedup_key", sa.String(length=256), nullable=False),
        sa.Column("title_key", sa.String(length=128), nullable=False),
        sa.Column("cause_key", sa.String(length=128), nullable=False),
        sa.Column("confidence", sa.String(length=16), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("state", sa.String(length=24), nullable=False),
        sa.Column("router_ids", sa.JSON(), nullable=False),
        sa.Column("device_ids", sa.JSON(), nullable=False),
        sa.Column("facts", sa.JSON(), nullable=False),
        sa.Column("recommendations", sa.JSON(), nullable=False),
        sa.Column("last_observed", sa.DateTime(), nullable=False),
        sa.Column("acknowledged_by", sa.String(length=36), nullable=True),
        sa.Column("assigned_to", sa.String(length=36), nullable=True),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["acknowledged_by"],
            ["administrators.id"],
        ),
        sa.ForeignKeyConstraint(
            ["assigned_to"],
            ["administrators.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("dedup_key"),
    )
    op.create_index(
        op.f("ix_incidents_created_at"), "incidents", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_incidents_last_observed"), "incidents", ["last_observed"], unique=False
    )
    op.create_index(op.f("ix_incidents_state"), "incidents", ["state"], unique=False)
    op.create_table(
        "maintenance_windows",
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("starts_at", sa.DateTime(), nullable=False),
        sa.Column("ends_at", sa.DateTime(), nullable=False),
        sa.Column("router_ids", sa.JSON(), nullable=False),
        sa.Column("device_ids", sa.JSON(), nullable=False),
        sa.Column("author_id", sa.String(length=36), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["author_id"],
            ["administrators.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_maintenance_windows_created_at"),
        "maintenance_windows",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_maintenance_windows_ends_at"),
        "maintenance_windows",
        ["ends_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_maintenance_windows_starts_at"),
        "maintenance_windows",
        ["starts_at"],
        unique=False,
    )
    op.create_table(
        "network_batches",
        sa.Column("author_id", sa.String(length=36), nullable=True),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("operation", sa.String(length=40), nullable=False),
        sa.Column("parameters", sa.JSON(), nullable=False),
        sa.Column("batch_size", sa.Integer(), nullable=False),
        sa.Column("stop_on_failure", sa.Boolean(), nullable=False),
        sa.Column("not_before", sa.DateTime(), nullable=False),
        sa.Column("window_end", sa.DateTime(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("automatic", sa.Boolean(), nullable=False),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["author_id"],
            ["administrators.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_network_batches_created_at"),
        "network_batches",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_network_batches_not_before"),
        "network_batches",
        ["not_before"],
        unique=False,
    )
    op.create_index(
        op.f("ix_network_batches_state"), "network_batches", ["state"], unique=False
    )
    op.create_table(
        "incident_history",
        sa.Column("incident_id", sa.String(length=36), nullable=False),
        sa.Column("actor_id", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_incident_history_created_at"),
        "incident_history",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_incident_history_incident_id"),
        "incident_history",
        ["incident_id"],
        unique=False,
    )
    op.create_table(
        "client_observations",
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("observed_at", sa.DateTime(), nullable=False),
        sa.Column("sequence", sa.String(length=64), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("device_id", "sequence"),
    )
    op.create_index(
        op.f("ix_client_observations_created_at"),
        "client_observations",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_client_observations_device_id"),
        "client_observations",
        ["device_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_client_observations_observed_at"),
        "client_observations",
        ["observed_at"],
        unique=False,
    )
    op.create_table(
        "operation_targets",
        sa.Column("batch_id", sa.String(length=36), nullable=False),
        sa.Column("router_id", sa.String(length=36), nullable=True),
        sa.Column("device_id", sa.String(length=36), nullable=True),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("preview", sa.JSON(), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("deadline", sa.DateTime(), nullable=True),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["batch_id"],
            ["network_batches.id"],
        ),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.id"],
        ),
        sa.ForeignKeyConstraint(
            ["router_id"],
            ["routers.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("batch_id", "device_id"),
        sa.UniqueConstraint("batch_id", "router_id"),
    )
    op.create_index(
        op.f("ix_operation_targets_batch_id"),
        "operation_targets",
        ["batch_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_operation_targets_created_at"),
        "operation_targets",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_operation_targets_device_id"),
        "operation_targets",
        ["device_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_operation_targets_router_id"),
        "operation_targets",
        ["router_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_operation_targets_state"), "operation_targets", ["state"], unique=False
    )
    op.create_table(
        "owner_assignments",
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("full_name", sa.String(length=256), nullable=True),
        sa.Column("military_rank", sa.String(length=128), nullable=True),
        sa.Column("windows_account", sa.String(length=256), nullable=True),
        sa.Column("verified", sa.Boolean(), nullable=False),
        sa.Column("author_id", sa.String(length=36), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["author_id"],
            ["administrators.id"],
        ),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_owner_assignments_created_at"),
        "owner_assignments",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_owner_assignments_device_id"),
        "owner_assignments",
        ["device_id"],
        unique=False,
    )
    op.create_table(
        "user_identities",
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("windows_sid", sa.String(length=184), nullable=False),
        sa.Column("windows_account", sa.String(length=256), nullable=False),
        sa.Column("full_name", sa.String(length=256), nullable=False),
        sa.Column("military_rank", sa.String(length=128), nullable=True),
        sa.Column("verified_by", sa.String(length=36), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.id"],
        ),
        sa.ForeignKeyConstraint(
            ["verified_by"],
            ["administrators.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("device_id", "windows_sid"),
    )
    op.create_index(
        op.f("ix_user_identities_created_at"),
        "user_identities",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_user_identities_device_id"),
        "user_identities",
        ["device_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_user_identities_full_name"),
        "user_identities",
        ["full_name"],
        unique=False,
    )
    op.create_index(
        op.f("ix_user_identities_military_rank"),
        "user_identities",
        ["military_rank"],
        unique=False,
    )
    op.add_column(
        "device_groups",
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column(
        "devices", sa.Column("owner_name", sa.String(length=256), nullable=True)
    )
    op.add_column(
        "devices", sa.Column("owner_rank", sa.String(length=128), nullable=True)
    )
    op.add_column(
        "devices",
        sa.Column(
            "owner_verified", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
    )
    op.add_column(
        "devices", sa.Column("owner_account", sa.String(length=256), nullable=True)
    )
    op.add_column(
        "devices",
        sa.Column(
            "identity_status",
            sa.String(length=24),
            nullable=False,
            server_default="PENDING",
        ),
    )
    op.add_column(
        "devices", sa.Column("last_user_account", sa.String(length=256), nullable=True)
    )
    op.add_column(
        "devices", sa.Column("last_user_sid", sa.String(length=184), nullable=True)
    )
    op.add_column("devices", sa.Column("last_user_seen", sa.DateTime(), nullable=True))
    op.create_index(
        op.f("ix_devices_owner_name"), "devices", ["owner_name"], unique=False
    )
    op.create_index(
        op.f("ix_devices_owner_rank"), "devices", ["owner_rank"], unique=False
    )
    op.add_column(
        "routers",
        sa.Column(
            "role", sa.String(length=24), nullable=False, server_default="ROUTER"
        ),
    )
    op.add_column(
        "routers",
        sa.Column(
            "transport", sa.String(length=16), nullable=False, server_default="REST"
        ),
    )
    op.add_column(
        "routers",
        sa.Column("protected", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "routers",
        sa.Column("archived", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "routers",
        sa.Column("inventory", sa.JSON(), nullable=False, server_default="{}"),
    )
    op.add_column(
        "routers", sa.Column("health", sa.JSON(), nullable=False, server_default="{}")
    )
    op.add_column("routers", sa.Column("last_health", sa.DateTime(), nullable=True))
    op.add_column("routers", sa.Column("last_inventory", sa.DateTime(), nullable=True))
    op.add_column("routers", sa.Column("last_reboot", sa.DateTime(), nullable=True))
    op.add_column(
        "routers",
        sa.Column("desired_config", sa.JSON(), nullable=False, server_default="{}"),
    )
    op.add_column(
        "routers",
        sa.Column("recovery_policy", sa.JSON(), nullable=False, server_default="{}"),
    )
    op.add_column("routers", sa.Column("ssh_host_key", sa.Text(), nullable=True))
    op.add_column(
        "routers", sa.Column("config_hash", sa.String(length=64), nullable=True)
    )
    op.create_index(op.f("ix_routers_archived"), "routers", ["archived"], unique=False)


def downgrade():
    op.drop_table("system_settings")
    op.drop_index(op.f("ix_routers_archived"), table_name="routers")
    op.drop_column("routers", "ssh_host_key")
    op.drop_column("routers", "config_hash")
    op.drop_column("routers", "recovery_policy")
    op.drop_column("routers", "desired_config")
    op.drop_column("routers", "last_reboot")
    op.drop_column("routers", "last_inventory")
    op.drop_column("routers", "last_health")
    op.drop_column("routers", "health")
    op.drop_column("routers", "inventory")
    op.drop_column("routers", "archived")
    op.drop_column("routers", "protected")
    op.drop_column("routers", "transport")
    op.drop_column("routers", "role")
    op.drop_index(op.f("ix_devices_owner_rank"), table_name="devices")
    op.drop_index(op.f("ix_devices_owner_name"), table_name="devices")
    op.drop_column("devices", "last_user_seen")
    op.drop_column("devices", "last_user_sid")
    op.drop_column("devices", "last_user_account")
    op.drop_column("devices", "identity_status")
    op.drop_column("devices", "owner_account")
    op.drop_column("devices", "owner_verified")
    op.drop_column("devices", "owner_rank")
    op.drop_column("devices", "owner_name")
    op.drop_column("device_groups", "description")
    op.drop_index(
        op.f("ix_user_identities_military_rank"), table_name="user_identities"
    )
    op.drop_index(op.f("ix_user_identities_full_name"), table_name="user_identities")
    op.drop_index(op.f("ix_user_identities_device_id"), table_name="user_identities")
    op.drop_index(op.f("ix_user_identities_created_at"), table_name="user_identities")
    op.drop_table("user_identities")
    op.drop_index(
        op.f("ix_owner_assignments_device_id"), table_name="owner_assignments"
    )
    op.drop_index(
        op.f("ix_owner_assignments_created_at"), table_name="owner_assignments"
    )
    op.drop_table("owner_assignments")
    op.drop_index(op.f("ix_operation_targets_state"), table_name="operation_targets")
    op.drop_index(
        op.f("ix_operation_targets_router_id"), table_name="operation_targets"
    )
    op.drop_index(
        op.f("ix_operation_targets_device_id"), table_name="operation_targets"
    )
    op.drop_index(
        op.f("ix_operation_targets_created_at"), table_name="operation_targets"
    )
    op.drop_index(op.f("ix_operation_targets_batch_id"), table_name="operation_targets")
    op.drop_table("operation_targets")
    op.drop_index(
        op.f("ix_client_observations_observed_at"), table_name="client_observations"
    )
    op.drop_index(
        op.f("ix_client_observations_device_id"), table_name="client_observations"
    )
    op.drop_index(
        op.f("ix_client_observations_created_at"), table_name="client_observations"
    )
    op.drop_table("client_observations")
    op.drop_index(
        op.f("ix_incident_history_incident_id"), table_name="incident_history"
    )
    op.drop_index(op.f("ix_incident_history_created_at"), table_name="incident_history")
    op.drop_table("incident_history")
    op.drop_index(op.f("ix_network_batches_state"), table_name="network_batches")
    op.drop_index(op.f("ix_network_batches_not_before"), table_name="network_batches")
    op.drop_index(op.f("ix_network_batches_created_at"), table_name="network_batches")
    op.drop_table("network_batches")
    op.drop_index(
        op.f("ix_maintenance_windows_starts_at"), table_name="maintenance_windows"
    )
    op.drop_index(
        op.f("ix_maintenance_windows_ends_at"), table_name="maintenance_windows"
    )
    op.drop_index(
        op.f("ix_maintenance_windows_created_at"), table_name="maintenance_windows"
    )
    op.drop_table("maintenance_windows")
    op.drop_index(op.f("ix_incidents_state"), table_name="incidents")
    op.drop_index(op.f("ix_incidents_last_observed"), table_name="incidents")
    op.drop_index(op.f("ix_incidents_created_at"), table_name="incidents")
    op.drop_table("incidents")
    op.drop_index(
        op.f("ix_configuration_backups_router_id"), table_name="configuration_backups"
    )
    op.drop_index(
        op.f("ix_configuration_backups_created_at"), table_name="configuration_backups"
    )
    op.drop_table("configuration_backups")
    op.drop_index(op.f("ix_router_telemetry_router_id"), table_name="router_telemetry")
    op.drop_index(op.f("ix_router_telemetry_created_at"), table_name="router_telemetry")
    op.drop_table("router_telemetry")
    op.drop_table("ap_group_members")
    op.drop_index(op.f("ix_ap_groups_created_at"), table_name="ap_groups")
    op.drop_table("ap_groups")
