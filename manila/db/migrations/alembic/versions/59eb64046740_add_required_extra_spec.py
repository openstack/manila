# Copyright 2015 Mirantis, Inc.
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

"""Add required extra spec

Revision ID: 59eb64046740
Revises: 162a3e673105
Create Date: 2015-01-29 15:33:25.348140

"""

# revision identifiers, used by Alembic.
revision = '59eb64046740'
down_revision = '4ee2cf4be19a'

from alembic import op
from sqlalchemy import sql


def upgrade():
    connection = op.get_bind()

    def escape_column_name(name):
        return sql.column(name).compile(bind=connection)

    insert_required_extra_spec = (
        "INSERT INTO share_type_extra_specs "
        " (%(deleted)s, %(share_type_id)s, %(key)s, %(value)s)"
        " SELECT '0', st.id, 'driver_handles_share_servers', 'True'"
        " FROM share_types as st "
        " WHERE st.id NOT IN ( "
        " SELECT es.share_type_id FROM share_type_extra_specs as es "
        " WHERE es.spec_key = 'driver_handles_share_servers' )" % ({
            'deleted': escape_column_name('deleted'),
            'share_type_id': escape_column_name('share_type_id'),
            'key': escape_column_name('spec_key'),
            'value': escape_column_name('spec_value'),
        }))

    connection.execute(insert_required_extra_spec)


def downgrade():
    """Downgrade method.

    We can't determine, which extra specs should be removed after insertion,
    that's why do nothing here.
    """
    pass
