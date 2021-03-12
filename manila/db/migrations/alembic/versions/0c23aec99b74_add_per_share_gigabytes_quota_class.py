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

"""add_per_share_gigabytes_quota_class

Revision ID: 0c23aec99b74
Revises: 5aa813ae673d
Create Date: 2021-01-03 10:01:57.276225

"""

# revision identifiers, used by Alembic.
revision = '0c23aec99b74'
down_revision = '5aa813ae673d'

from alembic import op
from manila.db.migrations import utils
from oslo_log import log
from oslo_utils import timeutils
from sqlalchemy import MetaData

LOG = log.getLogger(__name__)


def upgrade():
    meta = MetaData()
    meta.bind = op.get_bind()
    connection = op.get_bind().connect()
    quota_classes_table = utils.load_table('quota_classes', connection)

    try:
        op.bulk_insert
        (quota_classes_table,
         [{'created_at': timeutils.utcnow(),
           'class_name': 'default',
           'resource': 'per_share_gigabytes',
           'hard_limit': -1,
           'deleted': False, }])
    except Exception:
        LOG.error("Default per_share_gigabytes row not inserted "
                  "into the quota_classes.")
        raise


def downgrade():
    """Don't delete the 'default' entries at downgrade time.

    We don't know if the user had default entries when we started.
    If they did, we wouldn't want to remove them.  So, the safest
    thing to do is just leave the 'default' entries at downgrade time.
    """
    pass
