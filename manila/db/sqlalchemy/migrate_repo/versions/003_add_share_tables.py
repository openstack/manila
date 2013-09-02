# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 NetApp
# All Rights Reserved.
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

from sqlalchemy import MetaData, Table, String, DateTime, Boolean
from sqlalchemy import Integer, Column, ForeignKey
from manila.openstack.common import log as logging

LOG = logging.getLogger(__name__)


def upgrade(migrate_engine):
    """Create shares and share_access_map tables."""
    meta = MetaData()
    meta.bind = migrate_engine

    shares = Table('shares', meta,
                   Column('created_at', DateTime),
                   Column('updated_at', DateTime),
                   Column('deleted_at', DateTime),
                   Column('deleted', Boolean),
                   Column('id', String(length=36),
                          primary_key=True, nullable=False),
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
                   Column('display_description',
                          String(length=255)),
                   Column('snapshot_id', String(length=36)),
                   Column('share_proto', String(255)),
                   Column('export_location', String(255)),
                   mysql_engine='InnoDB')

    access_map = Table('share_access_map', meta,
                       Column('created_at', DateTime),
                       Column('updated_at', DateTime),
                       Column('deleted_at', DateTime),
                       Column('deleted', Boolean),
                       Column('id', String(length=36),
                              primary_key=True, nullable=False),
                       Column('share_id', String(36), ForeignKey('shares.id'),
                              nullable=False),
                       Column('access_type', String(255)),
                       Column('access_to', String(255)),
                       Column('state', String(255)),
                       mysql_engine='InnoDB')

    shares.create()
    access_map.create()


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    shares = Table('shares', meta, autoload=True)
    access_map = Table('share_access_map', meta, autoload=True)
    access_map.drop()
    shares.drop()
