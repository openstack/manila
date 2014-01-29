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

    if migrate_engine.name != "sqlite":
        project_user_quotas = Table('project_user_quotas', meta, autoload=True)

        new_deleted = Column('new_deleted', Boolean, default=False)
        new_deleted.create(project_user_quotas, populate_default=True)

        project_user_quotas.update().\
            where(project_user_quotas.c.deleted == 1).\
            values(new_deleted=True).\
            execute()
        project_user_quotas.c.deleted.drop()
        project_user_quotas.c.new_deleted.alter(name="deleted")


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
