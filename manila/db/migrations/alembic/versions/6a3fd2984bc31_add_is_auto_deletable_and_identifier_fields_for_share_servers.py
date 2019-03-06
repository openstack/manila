# Copyright 2019 NetApp, Inc.
# All Rights Reserved.
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

"""Add is_auto_deletable and identifier fields for share servers

Revision ID: 6a3fd2984bc31
Revises: 11ee96se625f3
Create Date: 2018-10-29 11:27:44.194732

"""

# revision identifiers, used by Alembic.
revision = '6a3fd2984bc31'
down_revision = '11ee96se625f3'

from alembic import op
from oslo_log import log
import sqlalchemy as sa

from manila.db.migrations import utils


LOG = log.getLogger(__name__)


def upgrade():

    try:
        op.add_column('share_servers', sa.Column(
            'is_auto_deletable', sa.Boolean, default=True))
        op.add_column('share_servers', sa.Column(
            'identifier', sa.String(length=255), default=None))
    except Exception:
        LOG.error("Columns share_servers.is_auto_deletable "
                  "and/or share_servers.identifier not created!")
        raise

    try:
        connection = op.get_bind()
        share_servers_table = utils.load_table('share_servers', connection)
        for server in connection.execute(share_servers_table.select()):
            # pylint: disable=no-value-for-parameter
            connection.execute(
                share_servers_table.update().where(
                    share_servers_table.c.id == server.id,
                ).values({"identifier": server.id, "is_auto_deletable": True}))
    except Exception:
        LOG.error(
            "Could not initialize share_servers.is_auto_deletable to True"
            " and share_servers.identifier with the share server ID!")
        raise


def downgrade():
    try:
        op.drop_column('share_servers', 'is_auto_deletable')
        op.drop_column('share_servers', 'identifier')
    except Exception:
        LOG.error("Columns share_servers.is_auto_deletable and/or "
                  "share_servers.identifier not dropped!")
        raise
