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

from migrate.changeset import UniqueConstraint
from sqlalchemy import MetaData, Table

from manila.db.sqlalchemy import utils
from manila.openstack.common.gettextutils import _
from manila.openstack.common import log as logging

LOG = logging.getLogger(__name__)

UC_NAME = "net_subnet_uc"
OLD_COLUMNS = ('neutron_net_id', 'neutron_subnet_id', 'project_id')
NEW_COLUMNS = ('neutron_net_id', 'neutron_subnet_id', 'project_id', 'deleted')
TABLE_NAME = 'share_networks'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    utils.drop_unique_constraint(migrate_engine, TABLE_NAME, UC_NAME,
                                 *OLD_COLUMNS)

    t = Table(TABLE_NAME, meta, autoload=True)
    uc = UniqueConstraint(*NEW_COLUMNS, table=t, name=UC_NAME)
    uc.create()


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    utils.drop_unique_constraint(migrate_engine, TABLE_NAME, UC_NAME,
                                 *NEW_COLUMNS)

    t = Table(TABLE_NAME, meta, autoload=True)
    uc = UniqueConstraint(*OLD_COLUMNS, table=t, name=UC_NAME)
    uc.create()
