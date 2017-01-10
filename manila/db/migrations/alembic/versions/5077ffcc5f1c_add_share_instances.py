# Copyright 2015 Mirantis Inc.
# All Rights Reserved.
#
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

"""add_share_instances

Revision ID: 5077ffcc5f1c
Revises: 3db9992c30f3
Create Date: 2015-06-26 12:54:55.630152

"""

# revision identifiers, used by Alembic.
revision = '5077ffcc5f1c'
down_revision = '3db9992c30f3'


from alembic import op
from sqlalchemy import Column, DateTime, ForeignKey, String
import six

from manila.db.migrations import utils


def create_share_instances_table(connection):
    # Create 'share_instances' table
    share_instances_table = op.create_table(
        'share_instances',
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', String(length=36), default='False'),
        Column('id', String(length=36), primary_key=True, nullable=False),
        Column('share_id', String(length=36),
               ForeignKey('shares.id', name="si_share_fk")),
        Column('host', String(length=255)),
        Column('status', String(length=255)),
        Column('scheduled_at', DateTime),
        Column('launched_at', DateTime),
        Column('terminated_at', DateTime),
        Column('share_network_id', String(length=36),
               ForeignKey('share_networks.id', name="si_share_network_fk"),
               nullable=True),
        Column('share_server_id', String(length=36),
               ForeignKey('share_servers.id', name="si_share_server_fk"),
               nullable=True),
        Column('availability_zone', String(length=255)),
        mysql_engine='InnoDB',
        mysql_charset='utf8')

    # Migrate data from 'shares' to 'share_instances'
    share_instances = []
    shares_table = utils.load_table('shares', connection)
    for share in connection.execute(shares_table.select()):
        share_instances.append({
            'created_at': share.created_at,
            'updated_at': share.updated_at,
            'deleted_at': share.deleted_at,
            'deleted': share.deleted,
            'id': share.id,
            'share_id': share.id,
            'host': share.host,
            'status': share.status,
            'scheduled_at': share.scheduled_at,
            'launched_at': share.launched_at,
            'terminated_at': share.terminated_at,
            'share_network_id': share.share_network_id,
            'share_server_id': share.share_server_id,
            'availability_zone': share.availability_zone,
        })
    op.bulk_insert(share_instances_table, share_instances)

    # Remove columns moved to 'share_instances' table
    with op.batch_alter_table("shares") as batch_op:
        for fk in shares_table.foreign_keys:
            batch_op.drop_constraint(fk.name, type_='foreignkey')

        batch_op.drop_column('host')
        batch_op.drop_column('status')
        batch_op.drop_column('scheduled_at')
        batch_op.drop_column('launched_at')
        batch_op.drop_column('terminated_at')
        batch_op.drop_column('share_network_id')
        batch_op.drop_column('share_server_id')
        batch_op.drop_column('availability_zone')


def remove_share_instances_table(connection):
    with op.batch_alter_table("shares") as batch_op:
        batch_op.add_column(Column('host', String(length=255)))
        batch_op.add_column(Column('status', String(length=255)))
        batch_op.add_column(Column('scheduled_at', DateTime))
        batch_op.add_column(Column('launched_at', DateTime))
        batch_op.add_column(Column('terminated_at', DateTime))
        batch_op.add_column(Column('share_network_id', String(length=36),
                            ForeignKey('share_networks.id'),
                            nullable=True))
        batch_op.add_column(Column('share_server_id', String(length=36),
                            ForeignKey('share_servers.id'),
                            nullable=True))
        batch_op.add_column(Column('availability_zone', String(length=255)))

    shares_table = utils.load_table('shares', connection)
    share_inst_table = utils.load_table('share_instances', connection)

    for share in connection.execute(shares_table.select()):
        instance = connection.execute(
            share_inst_table.select().where(
                share_inst_table.c.share_id == share.id)
        ).first()

        op.execute(
            shares_table.update().where(
                shares_table.c.id == share.id
            ).values(
                {
                    'host': instance['host'],
                    'status': instance['status'],
                    'scheduled_at': instance['scheduled_at'],
                    'launched_at': instance['launched_at'],
                    'terminated_at': instance['terminated_at'],
                    'share_network_id': instance['share_network_id'],
                    'share_server_id': instance['share_server_id'],
                    'availability_zone': instance['availability_zone'],
                }
            )
        )

    op.drop_table('share_instances')


def create_snapshot_instances_table(connection):
    # Create 'share_snapshot_instances' table
    snapshot_instances_table = op.create_table(
        'share_snapshot_instances',
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', String(length=36), default='False'),
        Column('id', String(length=36), primary_key=True, nullable=False),
        Column('snapshot_id', String(length=36),
               ForeignKey('share_snapshots.id', name="ssi_snapshot_fk")),
        Column('share_instance_id', String(length=36),
               ForeignKey('share_instances.id', name="ssi_share_instance_fk")),
        Column('status', String(length=255)),
        Column('progress', String(length=255)),
        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    # Migrate data from share_snapshots to share_snapshot_instances
    snapshot_instances = []
    snapshot_table = utils.load_table('share_snapshots', connection)
    share_instances_table = utils.load_table('share_instances', connection)

    for snapshot in connection.execute(snapshot_table.select()):
        share_instances_rows = connection.execute(
            share_instances_table.select().where(
                share_instances_table.c.share_id == snapshot.share_id
            )
        )
        snapshot_instances.append({
            'created_at': snapshot.created_at,
            'updated_at': snapshot.updated_at,
            'deleted_at': snapshot.deleted_at,
            'deleted': snapshot.deleted,
            'id': snapshot.id,
            'snapshot_id': snapshot.id,
            'status': snapshot.status,
            'progress': snapshot.progress,
            'share_instance_id': share_instances_rows.first().id,
        })
    op.bulk_insert(snapshot_instances_table, snapshot_instances)

    # Remove columns moved to 'share_snapshot_instances' table
    with op.batch_alter_table("share_snapshots") as batch_op:
        batch_op.drop_column('status')
        batch_op.drop_column('progress')


def remove_snapshot_instances_table(connection):
    with op.batch_alter_table("share_snapshots") as batch_op:
        batch_op.add_column(Column('status', String(length=255)))
        batch_op.add_column(Column('progress', String(length=255)))

    snapshots_table = utils.load_table('share_snapshots', connection)
    snapshots_inst_table = utils.load_table('share_snapshot_instances',
                                            connection)

    for snapshot_instance in connection.execute(snapshots_inst_table.select()):
        snapshot = connection.execute(
            snapshots_table.select().where(
                snapshots_table.c.id == snapshot_instance.snapshot_id)
        ).first()

        op.execute(
            snapshots_table.update().where(
                snapshots_table.c.id == snapshot.id
            ).values(
                {
                    'status': snapshot_instance['status'],
                    'progress': snapshot_instance['progress'],
                }
            )
        )

    op.drop_table('share_snapshot_instances')


def upgrade_export_locations_table(connection):
    # Update 'share_export_locations' table
    op.add_column(
        'share_export_locations',
        Column('share_instance_id', String(36),
               ForeignKey('share_instances.id', name="sel_instance_id_fk"))
    )

    # Convert share_id to share_instance_id
    share_el_table = utils.load_table('share_export_locations', connection)
    share_instances_table = utils.load_table('share_instances', connection)
    for export in connection.execute(share_el_table.select()):
        share_instance = connection.execute(
            share_instances_table.select().where(
                share_instances_table.c.share_id == export.share_id)
        ).first()

        op.execute(
            share_el_table.update().where(
                share_el_table.c.id == export.id
            ).values({'share_instance_id': six.text_type(share_instance.id)})
        )
    with op.batch_alter_table("share_export_locations") as batch_op:
        batch_op.drop_constraint('sel_id_fk', type_='foreignkey')
        batch_op.drop_column('share_id')
        batch_op.rename_table('share_export_locations',
                              'share_instance_export_locations')


def downgrade_export_locations_table(connection):
    op.rename_table('share_instance_export_locations',
                    'share_export_locations')
    op.add_column(
        'share_export_locations',
        Column('share_id', String(36),
               ForeignKey('shares.id', name="sel_id_fk"))
    )

    # Convert share_instance_id to share_id
    share_el_table = utils.load_table('share_export_locations', connection)
    share_instances_table = utils.load_table('share_instances', connection)
    for export in connection.execute(share_el_table.select()):
        share_instance = connection.execute(
            share_instances_table.select().where(
                share_instances_table.c.id == export.share_instance_id)
        ).first()

        op.execute(
            share_el_table.update().where(
                share_el_table.c.id == export.id
            ).values({'share_id': six.text_type(share_instance.share_id)})
        )

    with op.batch_alter_table("share_export_locations") as batch_op:
        batch_op.drop_constraint('sel_instance_id_fk', type_='foreignkey')
        batch_op.drop_column('share_instance_id')


def upgrade():
    connection = op.get_bind()

    create_share_instances_table(connection)
    create_snapshot_instances_table(connection)
    upgrade_export_locations_table(connection)


def downgrade():
    """Remove share_instances and share_snapshot_instance tables.

    This method can lead to data loss because only first share/snapshot
    instance is saved in shares/snapshot table.
    """
    connection = op.get_bind()

    downgrade_export_locations_table(connection)
    remove_snapshot_instances_table(connection)
    remove_share_instances_table(connection)
