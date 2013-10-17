# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack Foundation
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

from sqlalchemy import Column, DateTime, Integer
from sqlalchemy import Index, UniqueConstraint, MetaData, String, Table

from manila.db.sqlalchemy import api as db
from manila.openstack.common.gettextutils import _
from manila.openstack.common import log as logging

LOG = logging.getLogger(__name__)


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine;
    # bind migrate_engine to your metadata
    meta = MetaData()
    meta.bind = migrate_engine

    # Add 'user_id' column to quota_usages table.
    quota_usages = Table('quota_usages', meta, autoload=True)
    user_id = Column('user_id',
                     String(length=255))
    quota_usages.create_column(user_id)

    # Add 'user_id' column to reservations table.
    reservations = Table('reservations', meta, autoload=True)
    user_id = Column('user_id',
                     String(length=255))
    reservations.create_column(user_id)

    project_user_quotas = Table('project_user_quotas', meta,
                        Column('id', Integer, primary_key=True,
                               nullable=False),
                        Column('created_at', DateTime),
                        Column('updated_at', DateTime),
                        Column('deleted_at', DateTime),
                        Column('deleted', Integer),
                        Column('user_id',
                               String(length=255),
                               nullable=False),
                        Column('project_id',
                               String(length=255),
                               nullable=False),
                        Column('resource',
                               String(length=25),
                               nullable=False),
                        Column('hard_limit', Integer, nullable=True),
                        mysql_engine='InnoDB',
                        mysql_charset='utf8',
                        )

    try:
        project_user_quotas.create()
    except Exception:
        LOG.exception("Exception while creating table 'project_user_quotas'")
        meta.drop_all(tables=[project_user_quotas])
        raise


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    quota_usages = Table('quota_usages', meta, autoload=True)
    reservations = Table('reservations', meta, autoload=True)

    quota_usages.drop_column('user_id')
    reservations.drop_column('user_id')

    project_user_quotas = Table('project_user_quotas', meta, autoload=True)
    try:
        project_user_quotas.drop()
    except Exception:
        LOG.error(_("project_user_quotas table not dropped"))
        raise
