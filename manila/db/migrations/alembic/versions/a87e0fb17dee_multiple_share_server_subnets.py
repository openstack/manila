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

"""multiple share server subnets

Revision ID: a87e0fb17dee
Revises: 1946cb97bb8d
Create Date: 2022-01-14 06:12:27.596130

"""

# revision identifiers, used by Alembic.
revision = 'a87e0fb17dee'
down_revision = '1946cb97bb8d'


from alembic import op
from oslo_log import log
import sqlalchemy as sa

from manila.db.migrations import utils


SHARE_SERVERS_TABLE = 'share_servers'
SHARE_SERVER_SUBNET_MAP_TABLE = 'share_server_share_network_subnet_mappings'
NETWORK_ALLOCATIONS_TABLE = 'network_allocations'
LOG = log.getLogger(__name__)


def upgrade():

    # Create mappings table.
    context = op.get_context()
    mysql_dl = context.bind.dialect.name == 'mysql'
    datetime_type = (sa.dialects.mysql.DATETIME(fsp=6)
                     if mysql_dl else sa.DateTime)
    try:
        share_server_fk_name = "fk_ss_sns_m_share_server_id_share_servers"
        share_network_subnet_fk_name = (
            "fk_ss_sns_m_share_network_subnet_id_share_network_subnets")
        server_subnet_mappings_table = op.create_table(
            SHARE_SERVER_SUBNET_MAP_TABLE,
            sa.Column('id', sa.Integer, primary_key=True, nullable=False),
            sa.Column('created_at', datetime_type),
            sa.Column('updated_at', datetime_type),
            sa.Column('deleted_at', datetime_type),
            sa.Column('deleted', sa.Integer, default=0),
            sa.Column(
                'share_server_id', sa.String(length=36),
                sa.ForeignKey('share_servers.id', name=share_server_fk_name),
                nullable=False),
            sa.Column(
                'share_network_subnet_id', sa.String(length=36),
                sa.ForeignKey('share_network_subnets.id',
                              name=share_network_subnet_fk_name),
                nullable=False),
            mysql_engine='InnoDB',
            mysql_charset='utf8')
    except Exception:
        LOG.error('Table %s could not be created.',
                  SHARE_SERVER_SUBNET_MAP_TABLE)
        raise

    # Populate the mappings table from the share servers table.
    try:
        connection = op.get_bind()
        share_servers_table = utils.load_table(SHARE_SERVERS_TABLE, connection)
        server_subnet_mappings = []
        for server in connection.execute(share_servers_table.select()):
            if server.share_network_subnet_id:
                server_subnet_mappings.append({
                    'created_at': server.created_at,
                    'updated_at': server.updated_at,
                    'deleted_at': server.deleted_at,
                    'deleted': 0 if server.deleted == 'False' else 1,
                    'share_server_id': server.id,
                    'share_network_subnet_id': server.share_network_subnet_id,
                })
        op.bulk_insert(server_subnet_mappings_table, server_subnet_mappings)
    except Exception:
        LOG.error('Table %s could not be populated from the %s table.',
                  SHARE_SERVER_SUBNET_MAP_TABLE, SHARE_SERVERS_TABLE)
        raise

    # add subnet id column to the allocations table.
    try:
        network_allocation_fk_name = (
            "fk_network_allocation_subnet_id_share_network_subnets")
        op.add_column(
            NETWORK_ALLOCATIONS_TABLE,
            sa.Column('share_network_subnet_id', sa.String(length=36),
                      sa.ForeignKey('share_network_subnets.id',
                                    name=network_allocation_fk_name))
        )
    except Exception:
        LOG.error("Could not add ForeignKey column 'share_network_subnet_id'"
                  "to table %s.", NETWORK_ALLOCATIONS_TABLE)
        raise

    # populate the allocation with its subnet id using the share server.
    network_allocation_table = utils.load_table(NETWORK_ALLOCATIONS_TABLE,
                                                connection)
    for alloc in connection.execute(network_allocation_table.select()):
        # admin allocations should not contain subnet id.
        if alloc['label'] == 'admin':
            continue

        server = connection.execute(
            share_servers_table.select().where(
                alloc['share_server_id'] == (
                    share_servers_table.c.id))).first()

        # pylint: disable=no-value-for-parameter
        op.execute(network_allocation_table.update().where(
            alloc['id'] == network_allocation_table.c.id).values(
            {'share_network_subnet_id': server['share_network_subnet_id']}))

    # add a new column to share_servers.
    try:
        op.add_column(
            SHARE_SERVERS_TABLE,
            sa.Column('network_allocation_update_support', sa.Boolean,
                      nullable=False, server_default=sa.sql.false()))
    except Exception:
        LOG.error("Table %s could not add column "
                  "'network_allocation_update_support'.",
                  SHARE_SERVERS_TABLE)
        raise

    # drop subnet id foreign key from share servers.
    try:
        share_serves_fk_name = (
            "fk_share_servers_share_network_subnet_id_share_network_subnets")
        if connection.engine.name == 'mysql':
            op.drop_constraint(share_serves_fk_name, SHARE_SERVERS_TABLE,
                               type_="foreignkey")
        op.drop_column(SHARE_SERVERS_TABLE, 'share_network_subnet_id')
    except Exception:
        LOG.error("Table %s could not drop column 'share_network_subnet_id'.",
                  SHARE_SERVERS_TABLE)
        raise


def downgrade():
    """Remove share_server_share_network_subnet_mapping table and new columns.

    This method can lead to data loss because the share server can have
    more than one subnet.
    """
    try:
        share_serves_fk_name = (
            "fk_share_servers_share_network_subnet_id_share_network_subnets")
        op.add_column(
            SHARE_SERVERS_TABLE,
            sa.Column(
                'share_network_subnet_id', sa.String(36),
                sa.ForeignKey('share_network_subnets.id',
                              name=share_serves_fk_name),
            )
        )

        connection = op.get_bind()
        server_subnet_mappings_table = utils.load_table(
            SHARE_SERVER_SUBNET_MAP_TABLE, connection)
        share_servers_table = utils.load_table(SHARE_SERVERS_TABLE,
                                               connection)
        session = sa.orm.Session(bind=connection.connect())
        for server in connection.execute(share_servers_table.select()):
            subnets = session.query(
                server_subnet_mappings_table).filter(
                    server['id'] == (
                        server_subnet_mappings_table.c.share_server_id)).all()

            if server['deleted'] != 'False' and len(subnets) > 1:
                LOG.warning('Share server %s is not deleted and it '
                            'has more than one subnet (%s subnets), '
                            'the downgrade may cause an inconsistent '
                            'environment.', server['id'], len(subnets))

            subnet_id = subnets[0].share_network_subnet_id if subnets else None

            # pylint: disable=no-value-for-parameter
            op.execute(share_servers_table.update().where(
                server['id'] == share_servers_table.c.id).values(
                {'share_network_subnet_id': subnet_id}))

        session.close_all()

    except Exception:
        LOG.error("'share_network_subnet_id' field in the %s table could not "
                  "be created and populated from %s table.",
                  SHARE_SERVERS_TABLE, SHARE_SERVER_SUBNET_MAP_TABLE)
        raise

    try:
        op.drop_table(SHARE_SERVER_SUBNET_MAP_TABLE)
    except Exception:
        LOG.error("Failed to drop table %s.", SHARE_SERVER_SUBNET_MAP_TABLE)
        raise

    try:
        op.drop_column(SHARE_SERVERS_TABLE,
                       'network_allocation_update_support')
    except Exception:
        LOG.error("Table %s failed to drop the column "
                  "'network_allocation_update_support'.", SHARE_SERVERS_TABLE)
        raise

    try:
        network_allocation_fk_name = (
            "fk_network_allocation_subnet_id_share_network_subnets")
        if connection.engine.name == 'mysql':
            op.drop_constraint(network_allocation_fk_name,
                               NETWORK_ALLOCATIONS_TABLE,
                               type_="foreignkey")
        op.drop_column(NETWORK_ALLOCATIONS_TABLE, 'share_network_subnet_id')
    except Exception:
        LOG.error("Column 'network_allocations.share_network_subnet_id' from "
                  "table %s failed to drop.", NETWORK_ALLOCATIONS_TABLE)
        raise
