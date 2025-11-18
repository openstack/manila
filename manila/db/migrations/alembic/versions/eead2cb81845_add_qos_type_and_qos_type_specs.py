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

"""add qos type and qos type specs

Revision ID: eead2cb81845
Revises: e975ea83b712
Create Date: 2026-11-18 13:41:35.486013

"""

# revision identifiers, used by Alembic.
revision = 'eead2cb81845'
down_revision = 'e975ea83b712'

from alembic import op
from oslo_log import log
import sqlalchemy as sa


LOG = log.getLogger(__name__)


qos_types_table = 'qos_types'
qos_type_specs_table = 'qos_type_specs'
share_instances_table = 'share_instances'


def upgrade():
    """Add QoS type and QoS type specs tables."""

    context = op.get_context()
    mysql_dl = context.bind.dialect.name == 'mysql'
    datetime_type = (sa.dialects.mysql.DATETIME(fsp=6)
                     if mysql_dl else sa.DateTime)

    try:
        op.create_table(
            qos_types_table,
            sa.Column('id', sa.String(length=36),
                      primary_key=True, nullable=False),
            sa.Column('created_at', datetime_type),
            sa.Column('updated_at', datetime_type),
            sa.Column('deleted_at', datetime_type),
            sa.Column('deleted', sa.String(36), default='False'),
            sa.Column('name', sa.String(255)),
            sa.UniqueConstraint('name', 'deleted', name='uc_qos_type_name'),
            sa.Column('description', sa.String(255)),
            mysql_engine='InnoDB',
            mysql_charset='utf8'
        )
    except Exception:
        LOG.error("Table |%s| not created!", qos_types_table)
        raise

    try:
        op.create_table(
            qos_type_specs_table,
            sa.Column('id', sa.Integer, primary_key=True, nullable=False),
            sa.Column('created_at', datetime_type),
            sa.Column('updated_at', datetime_type),
            sa.Column('deleted_at', datetime_type),
            sa.Column('deleted', sa.String(36), default='False'),
            sa.Column('qos_type_id', sa.String(length=36),
                      sa.ForeignKey('qos_types.id',
                                    name='qos_type_specs_ibfk_1')),
            sa.Column('key', sa.String(length=255)),
            sa.Column('value', sa.String(length=255)),
            mysql_engine='InnoDB',
            mysql_charset='utf8'
        )
    except Exception:
        LOG.error("Table |%s| not created!", qos_type_specs_table)
        raise

    try:
        op.add_column(
            share_instances_table,
            sa.Column('qos_type_id', sa.String(36),
                      sa.ForeignKey('qos_types.id', name="qt_id_fk"),
                      nullable=True))
    except Exception:
        LOG.error("Column can not be added for 'share_instance' table!")
        raise


def downgrade():
    try:
        connection = op.get_bind()
        if connection.engine.name == 'mysql':
            # Drops necessary constraint from share servers table. Only mysql
            # needs constraint handling. Postgresql/sqlite don't
            op.drop_constraint("qt_id_fk", share_instances_table,
                               type_="foreignkey")
        op.drop_column(share_instances_table, 'qos_type_id')
    except Exception:
        LOG.error("Column can not be dropped for 'share_instances' table!")
        raise

    try:
        op.drop_table(qos_type_specs_table)
    except Exception:
        LOG.error("%s table not dropped", qos_type_specs_table)
        raise

    try:
        op.drop_table(qos_types_table)
    except Exception:
        LOG.error("%s table not dropped", qos_types_table)
        raise
