# Copyright 2015 Mirantis Inc.
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

from oslo_db.sqlalchemy import orm
import sqlalchemy

from manila.common import constants


class Query(orm.Query):
    def soft_delete(self, synchronize_session='evaluate', update_status=False,
                    status_field_name='status'):
        if update_status:
            setattr(self, status_field_name, constants.STATUS_DELETED)

        return super(Query, self).soft_delete(synchronize_session)


def get_maker(engine, autocommit=True, expire_on_commit=False):
    """Return a SQLAlchemy sessionmaker using the given engine."""
    return sqlalchemy.orm.sessionmaker(bind=engine,
                                       class_=orm.Session,
                                       autocommit=autocommit,
                                       expire_on_commit=expire_on_commit,
                                       query_cls=Query)

# NOTE(uglide): Monkey patch oslo_db get_maker() function to use custom Query
orm.get_maker = get_maker
