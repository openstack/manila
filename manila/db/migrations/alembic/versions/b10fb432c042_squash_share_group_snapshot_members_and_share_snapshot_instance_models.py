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

"""Squash 'share_group_snapshot_members' and 'share_snapshot_instances' models.

Revision ID: 31252d671ae5
Revises: 5237b6625330
Create Date: 2017-02-28 15:35:27.500063

"""

# revision identifiers, used by Alembic.
revision = '31252d671ae5'
down_revision = '5237b6625330'

from alembic import op
import sqlalchemy as sa

from manila.db.migrations import utils

SSI_TABLE_NAME = 'share_snapshot_instances'
SGSM_TABLE_NAME = 'share_group_snapshot_members'


def upgrade():
    # Update 'share_snapshot_instance' table with new fields
    op.add_column(SSI_TABLE_NAME, sa.Column('user_id', sa.String(255)))
    op.add_column(SSI_TABLE_NAME, sa.Column('project_id', sa.String(255)))
    op.add_column(SSI_TABLE_NAME, sa.Column('size', sa.Integer))
    op.add_column(SSI_TABLE_NAME, sa.Column('share_proto', sa.String(255)))
    op.add_column(
        SSI_TABLE_NAME, sa.Column('share_group_snapshot_id', sa.String(36)))

    # Drop FK for 'snapshot_id' because it will be null in case of SGS member
    op.drop_constraint('ssi_snapshot_fk', SSI_TABLE_NAME, type_='foreignkey')

    # Move existing SG snapshot members to share snapshot instance table
    connection = op.get_bind()
    ssi_table = utils.load_table(SSI_TABLE_NAME, connection)
    ssgm_table = utils.load_table(SGSM_TABLE_NAME, connection)
    ported_data = []
    for ssgm_record in connection.execute(ssgm_table.select()):
        ported_data.append({
            "id": ssgm_record.id,
            "share_group_snapshot_id": ssgm_record.share_group_snapshot_id,
            "share_instance_id": ssgm_record.share_instance_id,
            "size": ssgm_record.size,
            "status": ssgm_record.status,
            "share_proto": ssgm_record.share_proto,
            "user_id": ssgm_record.user_id,
            "project_id": ssgm_record.project_id,
            "provider_location": ssgm_record.provider_location,
            "created_at": ssgm_record.created_at,
            "updated_at": ssgm_record.updated_at,
            "deleted_at": ssgm_record.deleted_at,
            "deleted": ssgm_record.deleted,
        })
    op.bulk_insert(ssi_table, ported_data)

    # Delete 'share_group_snapshot_members' table
    op.drop_table(SGSM_TABLE_NAME)


def downgrade():
    # Create 'share_group_snapshot_members' table
    op.create_table(
        SGSM_TABLE_NAME,
        sa.Column('id', sa.String(36), primary_key=True, nullable=False),
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('deleted', sa.String(36), default='False'),
        sa.Column('user_id', sa.String(length=255), nullable=False),
        sa.Column('project_id', sa.String(length=255), nullable=False),
        sa.Column(
            'share_group_snapshot_id', sa.String(length=36),
            sa.ForeignKey(
                'share_group_snapshots.id', name='fk_gsm_group_snapshot_id'),
            nullable=False),
        sa.Column(
            'share_instance_id', sa.String(length=36),
            sa.ForeignKey(
                'share_instances.id', name='fk_gsm_share_instance_id'),
            nullable=False),
        sa.Column(
            'share_id', sa.String(length=36),
            sa.ForeignKey('shares.id', name='fk_gsm_share_id'),
            nullable=False),
        sa.Column('size', sa.Integer),
        sa.Column('status', sa.String(length=255)),
        sa.Column('share_proto', sa.String(length=255)),
        sa.Column('provider_location', sa.String(255), nullable=True),
        mysql_engine='InnoDB',
        mysql_charset='utf8')

    # Select all share snapshot instances that
    # have not null 'share_snapshot_group_id' to new table
    connection = op.get_bind()
    ssi_table = utils.load_table(SSI_TABLE_NAME, connection)
    share_instances_table = utils.load_table("share_instances", connection)
    ssgm_table = utils.load_table(SGSM_TABLE_NAME, connection)
    ported_data = []
    for row in connection.execute(
            ssi_table.join(
                share_instances_table,
                share_instances_table.c.id == ssi_table.c.share_instance_id
            ).select(use_labels=True).where(
                ssi_table.c.share_group_snapshot_id.isnot(None),
            )):
        ported_data.append({
            "id": row.share_snapshot_instances_id,
            "share_group_snapshot_id": (
                row.share_snapshot_instances_share_group_snapshot_id),
            "share_id": row.share_instances_share_id,
            "share_instance_id": row.share_instances_id,
            "size": row.share_snapshot_instances_size,
            "status": row.share_snapshot_instances_status,
            "share_proto": row.share_snapshot_instances_share_proto,
            "user_id": row.share_snapshot_instances_user_id,
            "project_id": row.share_snapshot_instances_project_id,
            "provider_location": (
                row.share_snapshot_instances_provider_location),
            "created_at": row.share_snapshot_instances_created_at,
            "updated_at": row.share_snapshot_instances_updated_at,
            "deleted_at": row.share_snapshot_instances_deleted_at,
            "deleted": row.share_snapshot_instances_deleted or "False",
        })

    # Copy share group snapshot members to new table
    op.bulk_insert(ssgm_table, ported_data)

    # Remove copied records from source table
    connection.execute(
        ssi_table.delete().where(
            ssi_table.c.share_group_snapshot_id.isnot(None)))

    # Remove redundant fields from 'share_snapshot_instance' table
    for column_name in ('user_id', 'project_id', 'size', 'share_proto',
                        'share_group_snapshot_id'):
        op.drop_column(SSI_TABLE_NAME, column_name)

    # Add back FK for 'snapshot_id' field
    op.create_foreign_key(
        'ssi_snapshot_fk', SSI_TABLE_NAME, 'share_snapshots',
        ['snapshot_id'], ['id'])
