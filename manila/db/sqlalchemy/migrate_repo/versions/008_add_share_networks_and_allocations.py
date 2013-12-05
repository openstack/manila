# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Mirantis Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from migrate import ForeignKeyConstraint
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer
from sqlalchemy import MetaData, String, Table, UniqueConstraint

from manila.openstack.common.gettextutils import _
from manila.openstack.common import log as logging

LOG = logging.getLogger(__name__)


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    shares = Table('shares', meta, autoload=True)
    Table('security_services', meta, autoload=True)

    share_networks = Table(
        'share_networks', meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Boolean, default=False),
        Column('id', String(length=36), primary_key=True,
               nullable=False),
        Column('project_id', String(length=36), nullable=False),
        Column('neutron_net_id', String(length=36), nullable=True),
        Column('neutron_subnet_id', String(length=36), nullable=True),
        Column('network_type', String(length=32), nullable=True),
        Column('segmentation_id', Integer, nullable=True),
        Column('cidr', String(length=64), nullable=True),
        Column('ip_version', Integer, nullable=True),
        Column('name', String(length=255), nullable=True),
        Column('description', String(length=255), nullable=True),
        Column('status', String(length=32)),
        UniqueConstraint('neutron_net_id', 'neutron_subnet_id', 'project_id',
                         name='net_subnet_uc'),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    allocations = Table(
        'network_allocations', meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Boolean, default=False),
        Column('id', String(length=36), primary_key=True, nullable=False),
        Column('ip_address', String(length=64), nullable=True),
        Column('mac_address', String(length=32), nullable=True),
        Column('share_network_id', String(length=36),
               ForeignKey('share_networks.id'), nullable=False),
        Column('status', String(length=32)),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    association = Table(
        'share_network_security_service_association', meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Boolean, default=False),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('share_network_id', String(length=36),
               ForeignKey('share_networks.id'), nullable=False),
        Column('security_service_id', String(length=36),
               ForeignKey('security_services.id'), nullable=False),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    tables = [share_networks, allocations, association]
    for table in tables:
        try:
            table.create()
        except Exception:
            LOG.exception(_("Exception while creating table"))
            meta.drop_all(tables=tables)
            raise

    network_id = Column('share_network_id',
                        String(length=36),
                        ForeignKey('share_networks.id'),
                        nullable=True)
    network_id.create(shares)


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    shares = Table('shares', meta, autoload=True)
    share_networks = Table('share_networks', meta, autoload=True)
    network_allocations = Table('network_allocations', meta, autoload=True)
    association = Table('share_network_security_service_association',
                        meta,
                        autoload=True)

    if migrate_engine.name == 'mysql':
        fkeys = list(shares.c.share_network_id.foreign_keys)
        params = {'columns': [shares.c['share_network_id']],
                  'refcolumns': [share_networks.c['id']],
                  'name': fkeys[0].constraint.name}
        with migrate_engine.begin():
            fkey = ForeignKeyConstraint(**params)
            fkey.drop()

    shares.c.share_network_id.drop()
    network_allocations.drop()
    association.drop()
    share_networks.drop()
