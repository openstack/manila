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

"""add_availability_zones_table

Revision ID: 1f0bd302c1a6
Revises: 579c267fbb4d
Create Date: 2015-07-24 12:09:36.008570

"""

# revision identifiers, used by Alembic.
revision = '1f0bd302c1a6'
down_revision = '579c267fbb4d'

from alembic import op
from oslo_utils import timeutils
from oslo_utils import uuidutils
from sqlalchemy import Column, DateTime, ForeignKey, String, UniqueConstraint

from manila.db.migrations import utils


def collect_existing_az_from_services_table(connection, services_table,
                                            az_table):
    az_name_to_id_mapping = dict()
    existing_az = []
    for service in connection.execute(services_table.select()):
        if service.availability_zone in az_name_to_id_mapping:
            continue

        az_id = uuidutils.generate_uuid()
        az_name_to_id_mapping[service.availability_zone] = az_id
        existing_az.append({
            'created_at': timeutils.utcnow(),
            'id': az_id,
            'name': service.availability_zone
        })

    op.bulk_insert(az_table, existing_az)

    return az_name_to_id_mapping


def upgrade():
    connection = op.get_bind()

    # Create new AZ table and columns
    availability_zones_table = op.create_table(
        'availability_zones',
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', String(length=36), default='False'),
        Column('id', String(length=36), primary_key=True, nullable=False),
        Column('name', String(length=255)),
        UniqueConstraint('name', 'deleted', name='az_name_uc'),
        mysql_engine='InnoDB',
        mysql_charset='utf8')

    for table_name, fk_name in (('services', 'service_az_id_fk'),
                                ('share_instances', 'si_az_id_fk')):
        op.add_column(
            table_name,
            Column('availability_zone_id', String(36),
                   ForeignKey('availability_zones.id', name=fk_name))
        )

    # Collect existing AZs from services table
    services_table = utils.load_table('services', connection)
    az_name_to_id_mapping = collect_existing_az_from_services_table(
        connection, services_table, availability_zones_table)

    # Map string AZ names to ID's in target tables
    set_az_id_in_table = lambda table, id, name: (
        op.execute(
            table.update().where(table.c.availability_zone == name).values(
                {'availability_zone_id': id})
        )
    )

    share_instances_table = utils.load_table('share_instances', connection)
    for name, id in az_name_to_id_mapping.items():
        for table_name in [services_table, share_instances_table]:
            set_az_id_in_table(table_name, id, name)

    # Remove old AZ columns from tables
    op.drop_column('services', 'availability_zone')
    op.drop_column('share_instances', 'availability_zone')


def downgrade():
    connection = op.get_bind()

    # Create old AZ fields
    op.add_column('services', Column('availability_zone', String(length=255)))
    op.add_column('share_instances',
                  Column('availability_zone', String(length=255)))

    # Migrate data
    az_table = utils.load_table('availability_zones', connection)
    share_instances_table = utils.load_table('share_instances', connection)
    services_table = utils.load_table('services', connection)

    for az in connection.execute(az_table.select()):
        op.execute(
            share_instances_table.update().where(
                share_instances_table.c.availability_zone_id == az.id
            ).values({'availability_zone': az.name})
        )
        op.execute(
            services_table.update().where(
                services_table.c.availability_zone_id == az.id
            ).values({'availability_zone': az.name})
        )

    # Remove AZ_id columns and AZ table
    op.drop_constraint('service_az_id_fk', 'services', type_='foreignkey')
    op.drop_column('services', 'availability_zone_id')
    op.drop_constraint('si_az_id_fk', 'share_instances', type_='foreignkey')
    op.drop_column('share_instances', 'availability_zone_id')
    op.drop_table('availability_zones')
