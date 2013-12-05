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

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer
from sqlalchemy import MetaData, String, Table

from manila.openstack.common.gettextutils import _
from manila.openstack.common import log as logging

LOG = logging.getLogger(__name__)


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    shares = Table('shares', meta, autoload=True)

    share_metadata = Table('share_metadata', meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Boolean),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('share_id', String(length=36), ForeignKey('shares.id'),
               nullable=False),
        Column('key', String(length=255), nullable=False),
        Column('value', String(length=1023), nullable=False),
        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )
    try:
        share_metadata.create()
    except Exception:
        LOG.exception("Exception while creating table 'share_metadata'")
        meta.drop_all(tables=[share_metadata])
        raise


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    share_metadata = Table('share_metadata', meta, autoload=True)
    try:
        share_metadata.drop()
    except Exception:
        LOG.error(_("share_metadata table not dropped"))
        raise
