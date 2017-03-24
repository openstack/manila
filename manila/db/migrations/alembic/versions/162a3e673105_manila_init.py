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
from sqlalchemy import Boolean, Column, DateTime, ForeignKey
from sqlalchemy import Integer, MetaData, String, Table, UniqueConstraint

LOG = log.getLogger(__name__)


def upgrade():
    migrate_engine = op.get_bind().engine
    meta = MetaData()
    meta.bind = migrate_engine

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
               String(length=255,
                      convert_unicode=True,
                      unicode_error=None,
                      _warn_on_bytestring=False),
               index=True),
        Column('resource',
               String(length=255,
                      convert_unicode=True,
                      unicode_error=None,
                      _warn_on_bytestring=False)),
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
               String(length=255, convert_unicode=True,
                      unicode_error=None,
                      _warn_on_bytestring=False),
               index=True),
        Column('resource',
               String(length=255, convert_unicode=True,
                      unicode_error=None,
                      _warn_on_bytestring=False)),
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
               String(length=36,
                      convert_unicode=True,
                      unicode_error=None,
                      _warn_on_bytestring=False),
               nullable=False),
        Column('usage_id',
               Integer(),
               ForeignKey('quota_usages.id'),
               nullable=False),
        Column('project_id',
               String(length=255, convert_unicode=True,
                      unicode_error=None,
                      _warn_on_bytestring=False),
               index=True),
        Column('resource',
               String(length=255, convert_unicode=True,
                      unicode_error=None,
                      _warn_on_bytestring=False)),
        Column('delta', Integer(), nullable=False),
        Column('expire', DateTime(timezone=False)),
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
        Column('share_network_id',
               String(length=36),
               ForeignKey('share_networks.id'),
               nullable=True),
        Column('share_server_id',
               String(length=36),
               ForeignKey('share_servers.id'),
               nullable=True),
        Column('share_proto', String(255)),
        Column('export_location', String(255)),
        Column('volume_type_id', String(length=36)),
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
        Column('share_id', String(36), ForeignKey('shares.id'),
               nullable=False),
        Column('access_type', String(255)),
        Column('access_to', String(255)),
        Column('state', String(255)),
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
        Column('share_id', String(36), ForeignKey('shares.id'),
               nullable=False),
        Column('size', Integer),
        Column('status', String(length=255)),
        Column('progress', String(length=255)),
        Column('display_name', String(length=255)),
        Column('display_description', String(length=255)),
        Column('share_size', Integer),
        Column('share_proto', String(length=255)),
        Column('export_location', String(255)),
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
        Column('share_id', String(length=36), ForeignKey('shares.id'),
               nullable=False),
        Column('key', String(length=255), nullable=False),
        Column('value', String(length=1023), nullable=False),
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
        Column('share_network_id', String(length=36),
               ForeignKey('share_networks.id'), nullable=True),
        Column('host', String(length=255), nullable=True),
        Column('status', String(length=32)),
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
        Column('share_server_id', String(length=36),
               ForeignKey('share_servers.id'),
               nullable=False),
        Column('key', String(length=255), nullable=False),
        Column('value', String(length=1023), nullable=False),
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
        Column('share_server_id', String(length=36),
               ForeignKey('share_servers.id'), nullable=False),
        Column('status', String(length=32)),
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
        Column('share_network_id', String(length=36),
               ForeignKey('share_networks.id'), nullable=False),
        Column('security_service_id', String(length=36),
               ForeignKey('security_services.id'), nullable=False),
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
        mysql_engine='InnoDB'
    )

    volume_type_extra_specs = Table(
        'volume_type_extra_specs', meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Boolean),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('volume_type_id', String(length=36),
               ForeignKey('volume_types.id'), nullable=False),
        Column('key', String(length=255)),
        Column('value', String(length=255)),
        mysql_engine='InnoDB'
    )

    # create all tables
    # Take care on create order for those with FK dependencies
    tables = [quotas, services, quota_classes, quota_usages,
              reservations, project_user_quotas, security_services,
              share_networks, ss_nw_association,
              share_servers, network_allocations, shares, access_map,
              share_snapshots, share_server_backend_details,
              share_metadata, volume_types, volume_type_extra_specs]

    for table in tables:
        if not table.exists():
            try:
                table.create()
            except Exception:
                LOG.info(repr(table))
                LOG.exception('Exception while creating table.')
                raise

    if migrate_engine.name == "mysql":
        tables = ["quotas", "services", "quota_classes", "quota_usages",
                  "reservations", "project_user_quotas", "share_access_map",
                  "share_snapshots", "share_metadata", "security_services",
                  "share_networks", "network_allocations", "shares",
                  "share_servers",
                  "share_network_security_service_association", "volume_types",
                  "volume_type_extra_specs", "share_server_backend_details"]

        migrate_engine.execute("SET foreign_key_checks = 0")
        for table in tables:
            migrate_engine.execute(
                "ALTER TABLE %s CONVERT TO CHARACTER SET utf8" % table)
        migrate_engine.execute("SET foreign_key_checks = 1")
        migrate_engine.execute(
            "ALTER DATABASE %s DEFAULT CHARACTER SET utf8" %
            migrate_engine.url.database)
        migrate_engine.execute("ALTER TABLE %s Engine=InnoDB" % table)


def downgrade():
    raise NotImplementedError('Downgrade from initial Manila install is not'
                              ' supported.')
