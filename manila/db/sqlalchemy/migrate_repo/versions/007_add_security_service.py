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

from sqlalchemy import Boolean, Column, DateTime
from sqlalchemy import MetaData, String, Table

from manila.openstack.common.gettextutils import _
from manila.openstack.common import log as logging

LOG = logging.getLogger(__name__)


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    security_services = Table(
        'security_services', meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Boolean, default=False),
        Column('id', String(length=36), primary_key=True, nullable=False),
        Column('project_id', String(length=36), nullable=False),
        Column('type', String(length=32), nullable=False),
        Column('dns_ip', String(length=64), nullable=True),
        Column('server', String(length=255), nullable=True),
        Column('domain', String(length=255), nullable=True),
        Column('sid', String(length=255), nullable=True),
        Column('name', String(length=255), nullable=True),
        Column('description', String(length=255), nullable=True),
        Column('status', String(length=16)),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    try:
        security_services.create()
    except Exception:
        LOG.exception(_("Exception while creating table"))
        raise


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    security_services = Table('security_services', meta, autoload=True)
    security_services.drop()
