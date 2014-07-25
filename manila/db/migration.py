# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import os

from manila.db.sqlalchemy import api as db_api
from manila import utils


IMPL = utils.LazyPluggable('db_backend',
                           sqlalchemy='oslo.db.sqlalchemy.migration')


INIT_VERSION = 000
MIGRATE_REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            'sqlalchemy/migrate_repo')


def db_sync(version=None):
    """Migrate the database to `version` or the most recent version."""
    return IMPL.db_sync(db_api.get_engine(), MIGRATE_REPO, version=version,
                        init_version=INIT_VERSION)


def db_version():
    """Display the current database version."""
    return IMPL.db_version(db_api.get_engine(), MIGRATE_REPO, INIT_VERSION)
