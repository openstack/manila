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

"""add_reservation_expire_index

Revision ID: 7d142971c4ef
Revises: d5db24264f5c
Create Date: 2017-03-02 09:19:27.114719

"""

# revision identifiers, used by Alembic.
revision = '7d142971c4ef'
down_revision = 'd5db24264f5c'

from alembic import op
from sqlalchemy import Index, MetaData, Table


def _reservation_index(method):
    meta = MetaData()
    meta.bind = op.get_bind().engine
    reservations = Table('reservations', meta, autoload=True)
    index = Index('reservations_deleted_expire_idx',
                  reservations.c.deleted, reservations.c.expire)
    getattr(index, method)(meta.bind)


def upgrade():
    _reservation_index('create')


def downgrade():
    _reservation_index('drop')
