# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Convert consistency groups to share groups

Revision ID: 03da71c0e321
Revises: e9f79621d83f
Create Date: 2016-05-19 10:25:17.899008

"""

# revision identifiers, used by Alembic.
revision = "03da71c0e321"
down_revision = "e9f79621d83f"

from alembic import op
from oslo_log import log
import sqlalchemy as sa
from sqlalchemy import Column, String

from manila.db.migrations import utils

LOG = log.getLogger(__name__)


def upgrade():
    LOG.info("Renaming consistency group tables")

    # Rename tables
    op.rename_table("consistency_groups", "share_groups")
    op.rename_table("cgsnapshots", "share_group_snapshots")
    op.rename_table("cgsnapshot_members", "share_group_snapshot_members")
    op.rename_table(
        "consistency_group_share_type_mappings",
        "share_group_share_type_mappings")

    # Update columns and foreign keys
    op.drop_constraint(
        "fk_shares_consistency_group_id", "shares", type_="foreignkey")
    op.alter_column(
        "shares", "consistency_group_id", existing_type=String(36),
        existing_nullable=True, new_column_name="share_group_id")
    op.alter_column(
        "shares", "source_cgsnapshot_member_id", existing_type=String(36),
        existing_nullable=True,
        new_column_name="source_share_group_snapshot_member_id")
    op.create_foreign_key(
        "fk_shares_share_group_id", "shares", "share_groups",
        ["share_group_id"], ["id"])
    op.drop_constraint(
        "fk_cg_share_network_id", "share_groups", type_="foreignkey")
    op.drop_constraint(
        "fk_cg_share_server_id", "share_groups", type_="foreignkey")
    op.alter_column(
        "share_groups", "source_cgsnapshot_id", existing_type=String(36),
        new_column_name="source_share_group_snapshot_id")
    op.create_foreign_key(
        "fk_share_group_share_network_id", "share_groups", "share_networks",
        ["share_network_id"], ["id"])
    op.create_foreign_key(
        "fk_share_group_share_server_id", "share_groups", "share_servers",
        ["share_server_id"], ["id"])
    op.drop_constraint(
        "fk_cgsnapshots_consistency_group_id", "share_group_snapshots",
        type_="foreignkey")
    op.alter_column(
        "share_group_snapshots", "consistency_group_id",
        existing_type=String(36), new_column_name="share_group_id")
    op.create_foreign_key(
        "fk_share_group_snapshots_share_group_id", "share_group_snapshots",
        "share_groups", ["share_group_id"], ["id"])
    op.drop_constraint(
        "fk_cgstm_cg_id", "share_group_share_type_mappings",
        type_="foreignkey")
    op.drop_constraint(
        "fk_cgstm_share_type_id", "share_group_share_type_mappings",
        type_="foreignkey")
    op.alter_column(
        "share_group_share_type_mappings", "consistency_group_id",
        existing_type=String(36), new_column_name="share_group_id")
    op.create_foreign_key(
        "fk_sgstm_share_group_id", "share_group_share_type_mappings",
        "share_groups", ["share_group_id"], ["id"])
    op.create_foreign_key(
        "fk_sgstm_share_type_id", "share_group_share_type_mappings",
        "share_types", ["share_type_id"], ["id"])
    op.drop_constraint(
        "fk_cgsnapshot_members_cgsnapshot_id", "share_group_snapshot_members",
        type_="foreignkey")
    op.drop_constraint(
        "fk_cgsnapshot_members_share_instance_id",
        "share_group_snapshot_members", type_="foreignkey")
    op.drop_constraint(
        "fk_cgsnapshot_members_share_id", "share_group_snapshot_members",
        type_="foreignkey")
    op.drop_constraint(
        "fk_cgsnapshot_members_share_type_id", "share_group_snapshot_members",
        type_="foreignkey")
    op.alter_column(
        "share_group_snapshot_members", "cgsnapshot_id",
        existing_type=String(36), new_column_name="share_group_snapshot_id")
    op.create_foreign_key(
        "fk_gsm_group_snapshot_id", "share_group_snapshot_members",
        "share_group_snapshots", ["share_group_snapshot_id"], ["id"])
    op.create_foreign_key(
        "fk_gsm_share_instance_id", "share_group_snapshot_members",
        "share_instances", ["share_instance_id"], ["id"])
    op.create_foreign_key(
        "fk_gsm_share_id", "share_group_snapshot_members", "shares",
        ["share_id"], ["id"])
    op.drop_column("share_group_snapshot_members", "share_type_id")


def downgrade():
    meta = sa.MetaData()
    meta.bind = op.get_bind()

    # Rename tables
    op.rename_table("share_groups", "consistency_groups")
    op.rename_table("share_group_snapshots", "cgsnapshots")
    op.rename_table("share_group_snapshot_members", "cgsnapshot_members")
    op.rename_table(
        "share_group_share_type_mappings",
        "consistency_group_share_type_mappings")

    # Update columns and foreign keys
    op.drop_constraint(
        "fk_shares_share_group_id", "shares", type_="foreignkey")
    op.alter_column(
        "shares", "share_group_id", existing_type=String(36),
        new_column_name="consistency_group_id")
    op.alter_column(
        "shares", "source_share_group_snapshot_member_id",
        existing_type=String(36), existing_nullable=True,
        new_column_name="source_cgsnapshot_member_id")
    op.create_foreign_key(
        "fk_shares_consistency_group_id", "shares", "consistency_groups",
        ["consistency_group_id"], ["id"])
    op.drop_constraint(
        "fk_share_group_share_network_id", "consistency_groups",
        type_="foreignkey")
    op.drop_constraint(
        "fk_share_group_share_server_id", "consistency_groups",
        type_="foreignkey")
    op.alter_column(
        "consistency_groups", "source_share_group_snapshot_id",
        existing_type=String(36), new_column_name="source_cgsnapshot_id")
    op.create_foreign_key(
        "fk_cg_share_network_id", "consistency_groups", "share_networks",
        ["share_network_id"], ["id"])
    op.create_foreign_key(
        "fk_cg_share_server_id", "consistency_groups", "share_servers",
        ["share_server_id"], ["id"])
    op.drop_constraint(
        "fk_share_group_snapshots_share_group_id", "cgsnapshots",
        type_="foreignkey")
    op.alter_column(
        "cgsnapshots", "share_group_id", existing_type=String(36),
        new_column_name="consistency_group_id")
    op.create_foreign_key(
        "fk_cgsnapshots_consistency_group_id", "cgsnapshots",
        "consistency_groups", ["consistency_group_id"], ["id"])
    op.drop_constraint(
        "fk_sgstm_share_group_id", "consistency_group_share_type_mappings",
        type_="foreignkey")
    op.drop_constraint(
        "fk_sgstm_share_type_id", "consistency_group_share_type_mappings",
        type_="foreignkey")
    op.alter_column(
        "consistency_group_share_type_mappings", "share_group_id",
        existing_type=String(36), new_column_name="consistency_group_id")
    op.create_foreign_key(
        "fk_cgstm_cg_id", "consistency_group_share_type_mappings",
        "consistency_groups", ["consistency_group_id"], ["id"])
    op.create_foreign_key(
        "fk_cgstm_share_type_id", "consistency_group_share_type_mappings",
        "share_types", ["share_type_id"], ["id"])
    op.drop_constraint(
        "fk_gsm_group_snapshot_id", "cgsnapshot_members", type_="foreignkey")
    op.drop_constraint(
        "fk_gsm_share_instance_id", "cgsnapshot_members", type_="foreignkey")
    op.drop_constraint(
        "fk_gsm_share_id", "cgsnapshot_members", type_="foreignkey")
    op.alter_column(
        "cgsnapshot_members", "share_group_snapshot_id",
        existing_type=String(36), new_column_name="cgsnapshot_id")
    op.create_foreign_key(
        "fk_cgsnapshot_members_cgsnapshot_id", "cgsnapshot_members",
        "cgsnapshots", ["cgsnapshot_id"], ["id"])
    op.create_foreign_key(
        "fk_cgsnapshot_members_share_instance_id",
        "cgsnapshot_members", "share_instances", ["share_instance_id"], ["id"])
    op.create_foreign_key(
        "fk_cgsnapshot_members_share_id", "cgsnapshot_members", "shares",
        ["share_id"], ["id"])
    op.add_column(
        "cgsnapshot_members",
        Column('share_type_id', String(36), nullable=True))

    connection = op.get_bind()
    si_table = utils.load_table('share_instances', connection)
    member_table = utils.load_table('cgsnapshot_members', connection)
    for si_record in connection.execute(si_table.select()):
        connection.execute(
            member_table.update().where(
                member_table.c.share_instance_id == si_record.id,
            ).values({"share_type_id": si_record.share_type_id}))

    op.alter_column(
        "cgsnapshot_members",
        Column('share_type_id', String(36), nullable=False))
    op.create_foreign_key(
        "fk_cgsnapshot_members_share_type_id", "cgsnapshot_members",
        "share_types", ["share_type_id"], ["id"])
