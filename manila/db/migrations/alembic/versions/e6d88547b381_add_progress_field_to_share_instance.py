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

"""add-progress-field-to-share-instance

Revision ID: e6d88547b381
Revises: 805685098bd2
Create Date: 2020-01-31 14:06:15.952747

"""

# revision identifiers, used by Alembic.
revision = 'e6d88547b381'
down_revision = '805685098bd2'

from alembic import op
from manila.common import constants
from manila.db.migrations import utils
from oslo_log import log
import sqlalchemy as sa


LOG = log.getLogger(__name__)


def upgrade():

    try:
        connection = op.get_bind()
        op.add_column('share_instances',
                      sa.Column('progress', sa.String(32), nullable=True,
                                default=None))
        share_instances_table = utils.load_table('share_instances', connection)

        updated_data = {'progress': '100%'}

        # pylint: disable=no-value-for-parameter
        op.execute(
            share_instances_table.update().where(
                share_instances_table.c.status == constants.STATUS_AVAILABLE,
            ).values(updated_data)
        )
    except Exception:
        LOG.error("Column share_instances.progress not created.")
        raise


def downgrade():
    try:
        op.drop_column('share_instances', 'progress')
    except Exception:
        LOG.error("Column share_instances.progress not dropped.")
        raise
