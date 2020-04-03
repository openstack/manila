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

"""Implementation of paginate query."""

from manila import exception
import sqlalchemy


def paginate_query(query, model, limit, sort_key='created_at',
                   sort_dir='desc', offset=None):
    """Returns a query with sorting / pagination criteria added.

    :param query: the query object to which we should add paging/sorting
    :param model: the ORM model class
    :param limit: maximum number of items to return
    :param sort_key: attributes by which results should be sorted, default is
                      created_at
    :param sort_dir: direction in which results should be sorted (asc, desc)
    :param offset: the number of items to skip from the marker or from the
                    first element.

    :rtype: sqlalchemy.orm.query.Query
    :return: The query with sorting/pagination added.
    """

    try:
        sort_key_attr = getattr(model, sort_key)
    except AttributeError:
        raise exception.InvalidInput(reason='Invalid sort key %s' % sort_key)
    if sort_dir == 'desc':
        query = query.order_by(sqlalchemy.desc(sort_key_attr))
    else:
        query = query.order_by(sqlalchemy.asc(sort_key_attr))

    if limit is not None:
        query = query.limit(limit)

    if offset:
        query = query.offset(offset)

    return query
