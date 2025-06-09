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

"""Add share server encryption

Revision ID: e975ea83b712
Revises: 0d8c8f6d54a4
Create Date: 2025-01-20 14:25:29.141460

"""

# revision identifiers, used by Alembic.
revision = 'e975ea83b712'
down_revision = '0d8c8f6d54a4'

from alembic import op
from oslo_log import log
import sqlalchemy as sa


LOG = log.getLogger(__name__)


encryption_refs_table = 'encryption_refs'
share_servers_table = 'share_servers'
share_instances_table = 'share_instances'


def upgrade():
    try:
        op.add_column(
            share_servers_table,
            sa.Column('encryption_key_ref', sa.String(36), nullable=True))
    except Exception:
        LOG.error("Column 'encryption_key_ref' can not be added to the "
                  "'share_servers' table!")
        raise

    try:
        op.add_column(
            share_servers_table,
            sa.Column('application_credential_id',
                      sa.String(36), nullable=True))
    except Exception:
        LOG.error("Column 'application_credential_id' can not be added to the "
                  "'share_servers' table!")
        raise

    try:
        op.add_column(
            share_instances_table,
            sa.Column('encryption_key_ref', sa.String(36), nullable=True))
    except Exception:
        LOG.error("Column can not be added to the 'share_instances' table!")
        raise

    context = op.get_context()
    mysql_dl = context.bind.dialect.name == 'mysql'
    datetime_type = (sa.dialects.mysql.DATETIME(fsp=6)
                     if mysql_dl else sa.DateTime)

    try:
        op.create_table(
            encryption_refs_table,
            sa.Column('id', sa.String(36), primary_key=True, nullable=False),
            sa.Column('share_server_id', sa.String(length=36),
                      sa.ForeignKey('share_servers.id'), unique=True),
            sa.Column('share_instance_id', sa.String(length=36),
                      sa.ForeignKey('share_instances.id'), unique=True),
            sa.Column('encryption_key_ref', sa.String(36), nullable=True),
            sa.Column('project_id', sa.String(length=255), nullable=False),
            sa.Column('deleted', sa.String(36), default='False'),
            sa.Column('created_at', datetime_type),
            sa.Column('updated_at', datetime_type),
            sa.Column('deleted_at', datetime_type),
            mysql_engine='InnoDB',
            mysql_charset='utf8'
        )
    except Exception:
        LOG.error("Table |%s| not created!", encryption_refs_table)
        raise


def downgrade():
    try:
        op.drop_table(encryption_refs_table)
    except Exception:
        LOG.error("%s table not dropped", encryption_refs_table)
        raise

    try:
        op.drop_column(share_servers_table, 'encryption_key_ref')
        op.drop_column(share_servers_table, 'application_credential_id')
    except Exception:
        LOG.error("Column can not be dropped for 'share_servers' table!")
        raise

    try:
        op.drop_column(share_instances_table, 'encryption_key_ref')
    except Exception:
        LOG.error("Column can not be dropped for 'share_instances' table!")
        raise
