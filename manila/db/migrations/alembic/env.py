# Copyright 2014 Mirantis Inc.
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

from __future__ import with_statement

from alembic import context

from manila.db.sqlalchemy import api as db_api
from manila.db.sqlalchemy import models as db_models


def run_migrations_online():
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.
    """
    engine = db_api.get_engine()
    connection = engine.connect()
    target_metadata = db_models.ManilaBase.metadata
    context.configure(connection=connection,  # pylint: disable=E1101
                      target_metadata=target_metadata)
    try:
        with context.begin_transaction():  # pylint: disable=E1101
            context.run_migrations()  # pylint: disable=E1101
    finally:
        connection.close()


run_migrations_online()
