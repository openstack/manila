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

"""backup_change_availability_zone_to_availability_zone_id

Revision ID: 2d708a9a3ba9
Revises: cb20f743ca7b
Create Date: 2023-08-24 11:01:41.134456

"""

# revision identifiers, used by Alembic.
revision = '2d708a9a3ba9'
down_revision = 'cb20f743ca7b'

from alembic import op
from sqlalchemy import Column, ForeignKey, String

from manila.db.migrations import utils


def collect_existing_az(az_table, connection):
    az_name_to_id_mapping = dict()
    for az in connection.execute(az_table.select()):
        if az.name in az_name_to_id_mapping:
            continue

        az_name_to_id_mapping[az.name] = az.id
    return az_name_to_id_mapping


def upgrade():
    connection = op.get_bind()

    op.add_column(
        'share_backups',
        Column('availability_zone_id', String(36),
               ForeignKey('availability_zones.id', name='sb_az_id_fk'))
    )

    # Collect existing AZs from availability_zones table
    availability_zones_table = utils.load_table(
        'availability_zones', connection)
    az_name_to_id_mapping = collect_existing_az(
        availability_zones_table, connection,)

    # Map string AZ names to ID's in target table
    # pylint: disable=no-value-for-parameter
    set_az_id_in_table = lambda table, id, name: (  # noqa: E731
        op.execute(
            table.update().where(table.c.availability_zone == name).values(
                {'availability_zone_id': id})
        )
    )

    share_backups_table = utils.load_table('share_backups', connection)
    for name, id in az_name_to_id_mapping.items():
        set_az_id_in_table(share_backups_table, id, name)

    # Remove old AZ columns from table
    op.drop_column('share_backups', 'availability_zone')


def downgrade():
    connection = op.get_bind()

    # Create old AZ fields
    op.add_column('share_backups',
                  Column('availability_zone', String(length=255)))

    # Migrate data
    az_table = utils.load_table('availability_zones', connection)
    share_backups_table = utils.load_table('share_backups', connection)

    for az in connection.execute(az_table.select()):
        # pylint: disable=no-value-for-parameter
        op.execute(
            share_backups_table.update().where(
                share_backups_table.c.availability_zone_id == az.id
            ).values({'availability_zone': az.name})
        )

    # Remove AZ_id columns and AZ table
    op.drop_constraint('sb_az_id_fk', 'share_backups', type_='foreignkey')
    op.drop_column('share_backups', 'availability_zone_id')
