# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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

"""Database setup and migration commands."""

from manila import utils


IMPL = utils.LazyPluggable(
    'db_backend', sqlalchemy='manila.db.migrations.alembic.migration')


def upgrade(version):
    """Upgrade database to 'version' or the most recent version."""
    return IMPL.upgrade(version)


def downgrade(version):
    """Downgrade database to 'version' or to initial state."""
    return IMPL.downgrade(version)


def version():
    """Display the current database version."""
    return IMPL.version()


def stamp(version):
    """Stamp database with 'version' or the most recent version."""
    return IMPL.stamp(version)


def revision(message, autogenerate):
    """Generate new migration script."""
    return IMPL.revision(message, autogenerate)
