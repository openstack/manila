# Copyright 2019 NetApp, Inc.
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

"""add_share_network_subnets_table_and_modify_share_networks_and_servers

Revision ID: 805685098bd2
Revises: 6a3fd2984bc31
Create Date: 2019-05-09 16:28:41.919714

"""

# revision identifiers, used by Alembic.
revision = '805685098bd2'
down_revision = '6a3fd2984bc31'

from alembic import op
from manila.db.migrations import utils
from oslo_log import log
from oslo_utils import uuidutils

import sqlalchemy as sa

LOG = log.getLogger(__name__)


def upgrade():
    # New table
    try:
        share_networks_fk_name = (
            "fk_share_network_subnets_share_network_id_share_networks")
        availability_zones_fk_name = (
            "fk_share_network_subnets_availaility_zone_id_availability_zones")
        share_network_subnets_table = op.create_table(
            'share_network_subnets',
            sa.Column('id', sa.String(36), primary_key=True, nullable=False),
            sa.Column('neutron_net_id', sa.String(36), nullable=True),
            sa.Column('neutron_subnet_id', sa.String(36), nullable=True),
            sa.Column('network_type', sa.String(32), nullable=True),
            sa.Column('cidr', sa.String(64), nullable=True),
            sa.Column('segmentation_id', sa.Integer, nullable=True),
            sa.Column('gateway', sa.String(64), nullable=True),
            sa.Column('mtu', sa.Integer, nullable=True),
            sa.Column('share_network_id', sa.String(36), sa.ForeignKey(
                'share_networks.id', name=share_networks_fk_name)),
            sa.Column('ip_version', sa.Integer, nullable=True),
            sa.Column('availability_zone_id', sa.String(36),
                      sa.ForeignKey('availability_zones.id',
                                    name=availability_zones_fk_name)),
            sa.Column('created_at', sa.DateTime),
            sa.Column('updated_at', sa.DateTime),
            sa.Column('deleted_at', sa.DateTime),
            sa.Column('deleted', sa.String(36), default='False'),
            mysql_engine='InnoDB',
            mysql_charset='utf8'
        )
    except Exception:
        LOG.error("Table |%s| not created!", 'share_network_subnets')
        raise

    share_serves_fk_name = (
        "fk_share_servers_share_network_subnet_id_share_network_subnets")
    op.add_column(
        'share_servers',
        sa.Column(
            'share_network_subnet_id', sa.String(36),
            sa.ForeignKey('share_network_subnets.id',
                          name=share_serves_fk_name),
        )
    )

    connection = op.get_bind()

    share_networks_table = utils.load_table('share_networks', connection)
    share_servers_table = utils.load_table('share_servers', connection)

    share_network_subnets = []

    # Get all share_networks and move all their data to share network subnet
    for share_network in connection.execute(share_networks_table.select()):
        share_network_subnet = {
            'id': uuidutils.generate_uuid(),
            'neutron_net_id': share_network.neutron_net_id,
            'neutron_subnet_id': share_network.neutron_subnet_id,
            'network_type': share_network.network_type,
            'cidr': share_network.cidr,
            'segmentation_id': share_network.segmentation_id,
            'gateway': share_network.gateway,
            'mtu': share_network.mtu,
            'share_network_id': share_network.id,
            'ip_version': share_network.ip_version,
            'created_at': share_network.created_at,
            'updated_at': share_network.updated_at,
            'deleted_at': share_network.deleted_at,
            'deleted': share_network.deleted,
        }
        share_network_subnets.append(share_network_subnet)

    # Insertions for the new share network subnets
    op.bulk_insert(share_network_subnets_table, share_network_subnets)

    # Updates the field share server table with the share network subnet id
    for sns in share_network_subnets:
        share_servers = connection.execute(share_servers_table.select().where(
            share_servers_table.c.share_network_id == sns['share_network_id']
        ))
        updated_data = {'share_network_subnet_id': sns['id']}
        _update_share_servers(share_servers, updated_data, share_servers_table)

    if connection.engine.name == 'mysql':
        # Drops necessary constraint from share servers table. Only mysql
        # needs constraint handling. Postgresql/sqlite don't
        op.drop_constraint("share_servers_ibfk_1", "share_servers",
                           type_="foreignkey")

    op.drop_column('share_servers', 'share_network_id')
    op.drop_column('share_networks', 'neutron_net_id')
    op.drop_column('share_networks', 'neutron_subnet_id')
    op.drop_column('share_networks', 'network_type')
    op.drop_column('share_networks', 'segmentation_id')
    op.drop_column('share_networks', 'gateway')
    op.drop_column('share_networks', 'mtu')
    op.drop_column('share_networks', 'cidr')
    op.drop_column('share_networks', 'ip_version')


def _update_share_servers(share_servers, updated_data, share_servers_table):
    for share_server in share_servers:
        # pylint: disable=no-value-for-parameter
        op.execute(
            share_servers_table.update().where(
                share_servers_table.c.id == share_server.id,
            ).values(updated_data)
        )


def retrieve_default_subnet(subnets):
    # NOTE (silvacarlose): A default subnet is that one which doesn't contain
    # an availability zone. If all the share networks contain an az, we can
    # retrieve whichever share network, then we pick up the first.
    for subnet in subnets:
        if subnet.availability_zone_id is None:
            return subnet

    return subnets[0] if subnets is not None else None


def downgrade():
    connection = op.get_bind()

    # Include again the removed fields in the share network table
    op.add_column('share_networks',
                  sa.Column('neutron_net_id', sa.String(36), nullable=True))
    op.add_column('share_networks',
                  sa.Column('neutron_subnet_id', sa.String(36), nullable=True))
    op.add_column('share_networks',
                  sa.Column('network_type', sa.String(32), nullable=True))
    op.add_column('share_networks',
                  sa.Column('cidr', sa.String(64), nullable=True))
    op.add_column('share_networks',
                  sa.Column('gateway', sa.String(64), nullable=True))
    op.add_column('share_networks',
                  sa.Column('mtu', sa.Integer, nullable=True))
    op.add_column('share_networks',
                  sa.Column('segmentation_id', sa.Integer, nullable=True))
    op.add_column('share_networks',
                  sa.Column('ip_version', sa.Integer, nullable=True))

    # Include again the removed field in the share server table
    op.add_column('share_servers',
                  sa.Column('share_network_id', sa.String(36),
                            sa.ForeignKey('share_networks.id',
                                          name="share_servers_ibfk_1")))

    share_networks_table = utils.load_table('share_networks', connection)
    share_servers_table = utils.load_table('share_servers', connection)
    subnets_table = utils.load_table('share_network_subnets', connection)

    for share_network in connection.execute(share_networks_table.select()):
        network_subnets = connection.execute(subnets_table.select().where(
            subnets_table.c.share_network_id == share_network.id))
        default_subnet = retrieve_default_subnet(network_subnets)

        if default_subnet is not None:
            op.execute(
                # pylint: disable=no-value-for-parameter
                share_networks_table.update().where(
                    share_networks_table.c.id == share_network.id,
                ).values({
                    'neutron_net_id': default_subnet.neutron_net_id,
                    'neutron_subnet_id': default_subnet.neutron_subnet_id,
                    'network_type': default_subnet.network_type,
                    'cidr': default_subnet.cidr,
                    'gateway': default_subnet.gateway,
                    'mtu': default_subnet.mtu,
                    'segmentation_id': default_subnet.segmentation_id,
                    'ip_version': default_subnet.ip_version,
                })
            )

        for network_subnet in network_subnets:
            share_servers = connection.execute(
                share_servers_table.select().where(
                    share_servers_table.c.share_network_subnet_id ==
                    network_subnet.id))
            updated_data = {'share_network_id': share_network.id}
            _update_share_servers(share_servers, updated_data,
                                  share_servers_table)

    share_serves_fk_name = (
        "fk_share_servers_share_network_subnet_id_share_network_subnets")
    if connection.engine.name == 'mysql':
        op.drop_constraint(share_serves_fk_name, "share_servers",
                           type_="foreignkey")
    op.drop_column('share_servers', 'share_network_subnet_id')
    try:
        op.drop_table('share_network_subnets')
    except Exception:
        LOG.error("Failed to drop 'share_network_subnets' table!")
        raise
