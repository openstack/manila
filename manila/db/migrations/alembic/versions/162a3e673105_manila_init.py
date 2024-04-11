# Copyright 2012 OpenStack LLC.
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

"""manila_init

Revision ID: 162a3e673105
Revises: None
Create Date: 2014-07-23 17:51:57.077203

"""

# revision identifiers, used by Alembic.
revision = '162a3e673105'
down_revision = None

from alembic import op
from oslo_log import log
from sqlalchemy import Boolean, Column, DateTime, ForeignKeyConstraint
from sqlalchemy import Integer, MetaData, String, Table, UniqueConstraint

LOG = log.getLogger(__name__)


def upgrade():
    migrate_engine = op.get_bind().engine
    meta = MetaData()

    services = Table(
        'services', meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Integer, default=0),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('host', String(length=255)),
        Column('binary', String(length=255)),
        Column('topic', String(length=255)),
        Column('report_count', Integer, nullable=False),
        Column('disabled', Boolean),
        Column('availability_zone', String(length=255)),
        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    quotas = Table(
        'quotas', meta,
        Column('id', Integer, primary_key=True, nullable=False),
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Integer, default=0),
        Column('project_id', String(length=255)),
        Column('resource', String(length=255), nullable=False),
        Column('hard_limit', Integer),
        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    quota_classes = Table(
        'quota_classes', meta,
        Column('created_at', DateTime(timezone=False)),
        Column('updated_at', DateTime(timezone=False)),
        Column('deleted_at', DateTime(timezone=False)),
        Column('deleted', Integer, default=0),
        Column('id', Integer(), primary_key=True),
        Column('class_name',
               String(length=255),
               index=True),
        Column('resource',
               String(length=255)),
        Column('hard_limit', Integer(), nullable=True),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    quota_usages = Table(
        'quota_usages', meta,
        Column('created_at', DateTime(timezone=False)),
        Column('updated_at', DateTime(timezone=False)),
        Column('deleted_at', DateTime(timezone=False)),
        Column('deleted', Integer, default=0),
        Column('id', Integer(), primary_key=True),
        Column('user_id', String(length=255)),
        Column('project_id',
               String(length=255),
               index=True),
        Column('resource',
               String(length=255)),
        Column('in_use', Integer(), nullable=False),
        Column('reserved', Integer(), nullable=False),
        Column('until_refresh', Integer(), nullable=True),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    reservations = Table(
        'reservations', meta,
        Column('created_at', DateTime(timezone=False)),
        Column('updated_at', DateTime(timezone=False)),
        Column('deleted_at', DateTime(timezone=False)),
        Column('deleted', Integer, default=0),
        Column('id', Integer(), primary_key=True),
        Column('user_id', String(length=255)),
        Column('uuid',
               String(length=36),
               nullable=False),
        Column('usage_id', Integer(), nullable=False),
        Column('project_id',
               String(length=255),
               index=True),
        Column('resource',
               String(length=255)),
        Column('delta', Integer(), nullable=False),
        Column('expire', DateTime(timezone=False)),
        ForeignKeyConstraint(['usage_id'], ['quota_usages.id']),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    project_user_quotas = Table(
        'project_user_quotas', meta,
        Column('id', Integer, primary_key=True, nullable=False),
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Integer, default=0),
        Column('user_id', String(length=255), nullable=False),
        Column('project_id', String(length=255), nullable=False),
        Column('resource', String(length=25), nullable=False),
        Column('hard_limit', Integer, nullable=True),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    shares = Table(
        'shares', meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', String(length=36), default='False'),
        Column('id', String(length=36), primary_key=True, nullable=False),
        Column('user_id', String(length=255)),
        Column('project_id', String(length=255)),
        Column('host', String(length=255)),
        Column('size', Integer),
        Column('availability_zone',
               String(length=255)),
        Column('status', String(length=255)),
        Column('scheduled_at', DateTime),
        Column('launched_at', DateTime),
        Column('terminated_at', DateTime),
        Column('display_name', String(length=255)),
        Column('display_description', String(length=255)),
        Column('snapshot_id', String(length=36)),
        Column('share_network_id', String(length=36), nullable=True),
        Column('share_server_id', String(length=36), nullable=True),
        Column('share_proto', String(255)),
        Column('export_location', String(255)),
        Column('volume_type_id', String(length=36)),
        ForeignKeyConstraint(['share_network_id'], ['share_networks.id']),
        ForeignKeyConstraint(['share_server_id'], ['share_servers.id']),
        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    access_map = Table(
        'share_access_map', meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', String(length=36), default='False'),
        Column('id', String(length=36), primary_key=True, nullable=False),
        Column('share_id', String(36), nullable=False),
        Column('access_type', String(255)),
        Column('access_to', String(255)),
        Column('state', String(255)),
        ForeignKeyConstraint(['share_id'], ['shares.id']),
        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    share_snapshots = Table(
        'share_snapshots', meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', String(length=36), default='False'),
        Column('id', String(length=36), primary_key=True, nullable=False),
        Column('user_id', String(length=255)),
        Column('project_id', String(length=255)),
        Column('share_id', String(36), nullable=False),
        Column('size', Integer),
        Column('status', String(length=255)),
        Column('progress', String(length=255)),
        Column('display_name', String(length=255)),
        Column('display_description', String(length=255)),
        Column('share_size', Integer),
        Column('share_proto', String(length=255)),
        Column('export_location', String(255)),
        ForeignKeyConstraint(['share_id'], ['shares.id']),
        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    share_metadata = Table(
        'share_metadata', meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Integer, default=0),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('share_id', String(length=36), nullable=False),
        Column('key', String(length=255), nullable=False),
        Column('value', String(length=1023), nullable=False),
        ForeignKeyConstraint(['share_id'], ['shares.id']),
        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    security_services = Table(
        'security_services', meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', String(length=36), default='False'),
        Column('id', String(length=36), primary_key=True, nullable=False),
        Column('project_id', String(length=36), nullable=False),
        Column('type', String(length=32), nullable=False),
        Column('dns_ip', String(length=64), nullable=True),
        Column('server', String(length=255), nullable=True),
        Column('domain', String(length=255), nullable=True),
        Column('user', String(length=255), nullable=True),
        Column('password', String(length=255), nullable=True),
        Column('name', String(length=255), nullable=True),
        Column('description', String(length=255), nullable=True),
        Column('status', String(length=16)),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    share_networks = Table(
        'share_networks', meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', String(length=36), default='False'),
        Column('id', String(length=36), primary_key=True, nullable=False),
        Column('project_id', String(length=36), nullable=False),
        Column('user_id', String(length=36)),
        Column('neutron_net_id', String(length=36), nullable=True),
        Column('neutron_subnet_id', String(length=36), nullable=True),
        Column('network_type', String(length=32), nullable=True),
        Column('segmentation_id', Integer, nullable=True),
        Column('cidr', String(length=64), nullable=True),
        Column('ip_version', Integer, nullable=True),
        Column('name', String(length=255), nullable=True),
        Column('description', String(length=255), nullable=True),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    share_servers = Table(
        'share_servers', meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', String(length=36), default='False'),
        Column('id', String(length=36), primary_key=True, nullable=False),
        Column('share_network_id', String(length=36), nullable=True),
        Column('host', String(length=255), nullable=True),
        Column('status', String(length=32)),
        ForeignKeyConstraint(['share_network_id'], ['share_networks.id']),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    share_server_backend_details = Table(
        'share_server_backend_details', meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', String(length=36), default=0),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('share_server_id', String(length=36), nullable=False),
        Column('key', String(length=255), nullable=False),
        Column('value', String(length=1023), nullable=False),
        ForeignKeyConstraint(['share_server_id'], ['share_servers.id']),
        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    network_allocations = Table(
        'network_allocations', meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', String(length=36), default='False'),
        Column('id', String(length=36), primary_key=True, nullable=False),
        Column('ip_address', String(length=64), nullable=True),
        Column('mac_address', String(length=32), nullable=True),
        Column('share_server_id', String(length=36), nullable=False),
        Column('status', String(length=32)),
        ForeignKeyConstraint(['share_server_id'], ['share_servers.id']),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    ss_nw_association = Table(
        'share_network_security_service_association', meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Integer, default=0),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('share_network_id', String(length=36), nullable=False),
        Column('security_service_id', String(length=36), nullable=False),
        ForeignKeyConstraint(['share_network_id'], ['share_networks.id']),
        ForeignKeyConstraint(['security_service_id'],
                             ['security_services.id']),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    volume_types = Table(
        'volume_types', meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', String(length=36), default='False'),
        Column('id', String(length=36), primary_key=True, nullable=False),
        Column('name', String(length=255)),
        UniqueConstraint('name', 'deleted', name='vt_name_uc'),
        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    volume_type_extra_specs = Table(
        'volume_type_extra_specs', meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Boolean),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('volume_type_id', String(length=36), nullable=False),
        Column('key', String(length=255)),
        Column('value', String(length=255)),
        ForeignKeyConstraint(['volume_type_id'], ['volume_types.id']),
        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    # create all tables
    # Take care on create order for those with FK dependencies
    tables = [quotas, services, quota_classes, quota_usages,
              reservations, project_user_quotas, security_services,
              share_networks, ss_nw_association,
              share_servers, network_allocations, shares, access_map,
              share_snapshots, share_server_backend_details,
              share_metadata, volume_types, volume_type_extra_specs]

    with migrate_engine.begin() as conn:
        for table in tables:

            try:
                table.create(conn, checkfirst=True)
            except Exception:
                LOG.info(repr(table))
                LOG.exception('Exception while creating table.')
                raise


def downgrade():
    raise NotImplementedError('Downgrade from initial Manila install is not'
                              ' supported.')
