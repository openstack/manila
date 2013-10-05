# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC.
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

from oslo.config import cfg
from sqlalchemy import Boolean, Column, DateTime, ForeignKey
from sqlalchemy import Integer, MetaData, String, Table


from manila.openstack.common import log as logging

CONF = cfg.CONF

LOG = logging.getLogger(__name__)


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    migrations = Table(
        'migrations', meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Boolean),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('source_compute', String(length=255)),
        Column('dest_compute', String(length=255)),
        Column('dest_host', String(length=255)),
        Column('status', String(length=255)),
        Column('instance_uuid', String(length=255)),
        Column('old_instance_type_id', Integer),
        Column('new_instance_type_id', Integer),
        mysql_engine='InnoDB'
    )

    services = Table(
        'services', meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Boolean),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('host', String(length=255)),
        Column('binary', String(length=255)),
        Column('topic', String(length=255)),
        Column('report_count', Integer, nullable=False),
        Column('disabled', Boolean),
        Column('availability_zone', String(length=255)),
        mysql_engine='InnoDB'
    )

    quotas = Table(
        'quotas', meta,
        Column('id', Integer, primary_key=True, nullable=False),
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Boolean),
        Column('project_id', String(length=255)),
        Column('resource', String(length=255), nullable=False),
        Column('hard_limit', Integer),
        mysql_engine='InnoDB'
    )

    # create all tables
    # Take care on create order for those with FK dependencies
    tables = [migrations,
              quotas,
              services]

    for table in tables:
        try:
            table.create()
        except Exception:
            LOG.info(repr(table))
            LOG.exception(_('Exception while creating table.'))
            raise

    if migrate_engine.name == "mysql":
        tables = ["migrate_version",
                  "migrations",
                  "quotas",
                  "services"]

        sql = "SET foreign_key_checks = 0;"
        for table in tables:
            sql += "ALTER TABLE %s CONVERT TO CHARACTER SET utf8;" % table
        sql += "SET foreign_key_checks = 1;"
        sql += "ALTER DATABASE %s DEFAULT CHARACTER SET utf8;" \
            % migrate_engine.url.database
        sql += "ALTER TABLE %s Engine=InnoDB;" % table
        migrate_engine.execute(sql)


def downgrade(migrate_engine):
    LOG.exception(_('Downgrade from initial Manila install is unsupported.'))
