# Copyright (c) 2011 X.commerce, a business unit of eBay Inc.
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright (c) 2014 Mirantis, Inc.
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

"""Implementation of SQLAlchemy backend."""

import copy
import datetime
from functools import wraps
import ipaddress
import sys
import warnings

# NOTE(uglide): Required to override default oslo_db Query class
import manila.db.sqlalchemy.query  # noqa

from oslo_config import cfg
from oslo_db import api as oslo_db_api
from oslo_db import exception as db_exc
from oslo_db import exception as db_exception
from oslo_db import options as db_options
from oslo_db.sqlalchemy import session
from oslo_db.sqlalchemy import utils as db_utils
from oslo_log import log
from oslo_utils import excutils
from oslo_utils import timeutils
from oslo_utils import uuidutils
import six
from sqlalchemy import MetaData
from sqlalchemy import or_
from sqlalchemy.orm import joinedload
from sqlalchemy.sql.expression import true
from sqlalchemy.sql import func

from manila.common import constants
from manila.db.sqlalchemy import models
from manila import exception
from manila.i18n import _
from manila import quota

CONF = cfg.CONF

LOG = log.getLogger(__name__)
QUOTAS = quota.QUOTAS

_DEFAULT_QUOTA_NAME = 'default'
PER_PROJECT_QUOTAS = []

_FACADE = None

_DEFAULT_SQL_CONNECTION = 'sqlite://'
db_options.set_defaults(cfg.CONF,
                        connection=_DEFAULT_SQL_CONNECTION)


def _create_facade_lazily():
    global _FACADE
    if _FACADE is None:
        _FACADE = session.EngineFacade.from_config(cfg.CONF)
    return _FACADE


def get_engine():
    facade = _create_facade_lazily()
    return facade.get_engine()


def get_session(**kwargs):
    facade = _create_facade_lazily()
    return facade.get_session(**kwargs)


def get_backend():
    """The backend is this module itself."""

    return sys.modules[__name__]


def is_admin_context(context):
    """Indicates if the request context is an administrator."""
    if not context:
        warnings.warn(_('Use of empty request context is deprecated'),
                      DeprecationWarning)
        raise Exception('die')
    return context.is_admin


def is_user_context(context):
    """Indicates if the request context is a normal user."""
    if not context:
        return False
    if context.is_admin:
        return False
    if not context.user_id or not context.project_id:
        return False
    return True


def authorize_project_context(context, project_id):
    """Ensures a request has permission to access the given project."""
    if is_user_context(context):
        if not context.project_id:
            raise exception.NotAuthorized()
        elif context.project_id != project_id:
            raise exception.NotAuthorized()


def authorize_user_context(context, user_id):
    """Ensures a request has permission to access the given user."""
    if is_user_context(context):
        if not context.user_id:
            raise exception.NotAuthorized()
        elif context.user_id != user_id:
            raise exception.NotAuthorized()


def authorize_quota_class_context(context, class_name):
    """Ensures a request has permission to access the given quota class."""
    if is_user_context(context):
        if not context.quota_class:
            raise exception.NotAuthorized()
        elif context.quota_class != class_name:
            raise exception.NotAuthorized()


def require_admin_context(f):
    """Decorator to require admin request context.

    The first argument to the wrapped function must be the context.

    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not is_admin_context(args[0]):
            raise exception.AdminRequired()
        return f(*args, **kwargs)
    return wrapper


def require_context(f):
    """Decorator to require *any* user or admin context.

    This does no authorization for user or project access matching, see
    :py:func:`authorize_project_context` and
    :py:func:`authorize_user_context`.

    The first argument to the wrapped function must be the context.

    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not is_admin_context(args[0]) and not is_user_context(args[0]):
            raise exception.NotAuthorized()
        return f(*args, **kwargs)
    return wrapper


def require_share_exists(f):
    """Decorator to require the specified share to exist.

    Requires the wrapped function to use context and share_id as
    their first two arguments.
    """
    @wraps(f)
    def wrapper(context, share_id, *args, **kwargs):
        share_get(context, share_id)
        return f(context, share_id, *args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper


def require_share_instance_exists(f):
    """Decorator to require the specified share instance to exist.

    Requires the wrapped function to use context and share_instance_id as
    their first two arguments.
    """
    @wraps(f)
    def wrapper(context, share_instance_id, *args, **kwargs):
        share_instance_get(context, share_instance_id)
        return f(context, share_instance_id, *args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper


def apply_sorting(model, query, sort_key, sort_dir):
    if sort_dir.lower() not in ('desc', 'asc'):
        msg = _("Wrong sorting data provided: sort key is '%(sort_key)s' "
                "and sort direction is '%(sort_dir)s'.") % {
                    "sort_key": sort_key, "sort_dir": sort_dir}
        raise exception.InvalidInput(reason=msg)

    sort_attr = getattr(model, sort_key)
    sort_method = getattr(sort_attr, sort_dir.lower())
    return query.order_by(sort_method())


def model_query(context, model, *args, **kwargs):
    """Query helper that accounts for context's `read_deleted` field.

    :param context: context to query under
    :param model: model to query. Must be a subclass of ModelBase.
    :param session: if present, the session to use
    :param read_deleted: if present, overrides context's read_deleted field.
    :param project_only: if present and context is user-type, then restrict
            query to match the context's project_id.
    """
    session = kwargs.get('session') or get_session()
    read_deleted = kwargs.get('read_deleted') or context.read_deleted
    project_only = kwargs.get('project_only')
    kwargs = dict()

    if project_only and not context.is_admin:
        kwargs['project_id'] = context.project_id
    if read_deleted in ('no', 'n', False):
        kwargs['deleted'] = False
    elif read_deleted in ('yes', 'y', True):
        kwargs['deleted'] = True

    return db_utils.model_query(
        model=model, session=session, args=args, **kwargs)


def exact_filter(query, model, filters, legal_keys):
    """Applies exact match filtering to a query.

    Returns the updated query.  Modifies filters argument to remove
    filters consumed.

    :param query: query to apply filters to
    :param model: model object the query applies to, for IN-style
                  filtering
    :param filters: dictionary of filters; values that are lists,
                    tuples, sets, or frozensets cause an 'IN' test to
                    be performed, while exact matching ('==' operator)
                    is used for other values
    :param legal_keys: list of keys to apply exact filtering to
    """

    filter_dict = {}

    # Walk through all the keys
    for key in legal_keys:
        # Skip ones we're not filtering on
        if key not in filters:
            continue

        # OK, filtering on this key; what value do we search for?
        value = filters.pop(key)

        if isinstance(value, (list, tuple, set, frozenset)):
            # Looking for values in a list; apply to query directly
            column_attr = getattr(model, key)
            query = query.filter(column_attr.in_(value))
        else:
            # OK, simple exact match; save for later
            filter_dict[key] = value

    # Apply simple exact matches
    if filter_dict:
        query = query.filter_by(**filter_dict)

    return query


def ensure_model_dict_has_id(model_dict):
    if not model_dict.get('id'):
        model_dict['id'] = uuidutils.generate_uuid()
    return model_dict


def _sync_shares(context, project_id, user_id, session, share_type_id=None):
    (shares, gigs) = share_data_get_for_project(
        context, project_id, user_id, share_type_id=share_type_id,
        session=session)
    return {'shares': shares}


def _sync_snapshots(context, project_id, user_id, session, share_type_id=None):
    (snapshots, gigs) = snapshot_data_get_for_project(
        context, project_id, user_id, share_type_id=share_type_id,
        session=session)
    return {'snapshots': snapshots}


def _sync_gigabytes(context, project_id, user_id, session, share_type_id=None):
    _junk, share_gigs = share_data_get_for_project(
        context, project_id, user_id, share_type_id=share_type_id,
        session=session)
    return {"gigabytes": share_gigs}


def _sync_snapshot_gigabytes(context, project_id, user_id, session,
                             share_type_id=None):
    _junk, snapshot_gigs = snapshot_data_get_for_project(
        context, project_id, user_id, share_type_id=share_type_id,
        session=session)
    return {"snapshot_gigabytes": snapshot_gigs}


def _sync_share_networks(context, project_id, user_id, session,
                         share_type_id=None):
    share_networks_count = count_share_networks(
        context, project_id, user_id, share_type_id=share_type_id,
        session=session)
    return {'share_networks': share_networks_count}


def _sync_share_groups(context, project_id, user_id, session,
                       share_type_id=None):
    share_groups_count = count_share_groups(
        context, project_id, user_id, share_type_id=share_type_id,
        session=session)
    return {'share_groups': share_groups_count}


def _sync_share_group_snapshots(context, project_id, user_id, session,
                                share_type_id=None):
    share_group_snapshots_count = count_share_group_snapshots(
        context, project_id, user_id, share_type_id=share_type_id,
        session=session)
    return {'share_group_snapshots': share_group_snapshots_count}


QUOTA_SYNC_FUNCTIONS = {
    '_sync_shares': _sync_shares,
    '_sync_snapshots': _sync_snapshots,
    '_sync_gigabytes': _sync_gigabytes,
    '_sync_snapshot_gigabytes': _sync_snapshot_gigabytes,
    '_sync_share_networks': _sync_share_networks,
    '_sync_share_groups': _sync_share_groups,
    '_sync_share_group_snapshots': _sync_share_group_snapshots,
}


###################


@require_admin_context
def service_destroy(context, service_id):
    session = get_session()
    with session.begin():
        service_ref = service_get(context, service_id, session=session)
        service_ref.soft_delete(session)


@require_admin_context
def service_get(context, service_id, session=None):
    result = (model_query(
        context,
        models.Service,
        session=session).
        filter_by(id=service_id).
        first())
    if not result:
        raise exception.ServiceNotFound(service_id=service_id)

    return result


@require_admin_context
def service_get_all(context, disabled=None):
    query = model_query(context, models.Service)

    if disabled is not None:
        query = query.filter_by(disabled=disabled)

    return query.all()


@require_admin_context
def service_get_all_by_topic(context, topic):
    return (model_query(
        context, models.Service, read_deleted="no").
        filter_by(disabled=False).
        filter_by(topic=topic).
        all())


@require_admin_context
def service_get_by_host_and_topic(context, host, topic):
    result = (model_query(
        context, models.Service, read_deleted="no").
        filter_by(disabled=False).
        filter_by(host=host).
        filter_by(topic=topic).
        first())
    if not result:
        raise exception.ServiceNotFound(service_id=host)
    return result


@require_admin_context
def _service_get_all_topic_subquery(context, session, topic, subq, label):
    sort_value = getattr(subq.c, label)
    return (model_query(context, models.Service,
                        func.coalesce(sort_value, 0),
                        session=session, read_deleted="no").
            filter_by(topic=topic).
            filter_by(disabled=False).
            outerjoin((subq, models.Service.host == subq.c.host)).
            order_by(sort_value).
            all())


@require_admin_context
def service_get_all_share_sorted(context):
    session = get_session()
    with session.begin():
        topic = CONF.share_topic
        label = 'share_gigabytes'
        subq = (model_query(context, models.Share,
                            func.sum(models.Share.size).label(label),
                            session=session, read_deleted="no").
                join(models.ShareInstance,
                     models.ShareInstance.share_id == models.Share.id).
                group_by(models.ShareInstance.host).
                subquery())
        return _service_get_all_topic_subquery(context,
                                               session,
                                               topic,
                                               subq,
                                               label)


@require_admin_context
def service_get_by_args(context, host, binary):
    result = (model_query(context, models.Service).
              filter_by(host=host).
              filter_by(binary=binary).
              first())

    if not result:
        raise exception.HostBinaryNotFound(host=host, binary=binary)

    return result


@require_admin_context
def service_create(context, values):
    session = get_session()

    _ensure_availability_zone_exists(context, values, session)

    service_ref = models.Service()
    service_ref.update(values)
    if not CONF.enable_new_services:
        service_ref.disabled = True

    with session.begin():
        service_ref.save(session)
        return service_ref


@require_admin_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def service_update(context, service_id, values):
    session = get_session()

    _ensure_availability_zone_exists(context, values, session, strict=False)

    with session.begin():
        service_ref = service_get(context, service_id, session=session)
        service_ref.update(values)
        service_ref.save(session=session)


###################


@require_context
def quota_get_all_by_project_and_user(context, project_id, user_id):
    authorize_project_context(context, project_id)
    user_quotas = model_query(
        context, models.ProjectUserQuota,
        models.ProjectUserQuota.resource,
        models.ProjectUserQuota.hard_limit,
    ).filter_by(
        project_id=project_id,
    ).filter_by(
        user_id=user_id,
    ).all()

    result = {'project_id': project_id, 'user_id': user_id}
    for u_quota in user_quotas:
        result[u_quota.resource] = u_quota.hard_limit
    return result


@require_context
def quota_get_all_by_project_and_share_type(context, project_id,
                                            share_type_id):
    authorize_project_context(context, project_id)
    share_type_quotas = model_query(
        context, models.ProjectShareTypeQuota,
        models.ProjectShareTypeQuota.resource,
        models.ProjectShareTypeQuota.hard_limit,
    ).filter_by(
        project_id=project_id,
    ).filter_by(
        share_type_id=share_type_id,
    ).all()

    result = {
        'project_id': project_id,
        'share_type_id': share_type_id,
    }
    for st_quota in share_type_quotas:
        result[st_quota.resource] = st_quota.hard_limit
    return result


@require_context
def quota_get_all_by_project(context, project_id):
    authorize_project_context(context, project_id)
    project_quotas = model_query(
        context, models.Quota, read_deleted="no",
    ).filter_by(
        project_id=project_id,
    ).all()

    result = {'project_id': project_id}
    for p_quota in project_quotas:
        result[p_quota.resource] = p_quota.hard_limit
    return result


@require_context
def quota_get_all(context, project_id):
    authorize_project_context(context, project_id)

    result = (model_query(context, models.ProjectUserQuota).
              filter_by(project_id=project_id).
              all())

    return result


@require_admin_context
def quota_create(context, project_id, resource, limit, user_id=None,
                 share_type_id=None):
    per_user = user_id and resource not in PER_PROJECT_QUOTAS

    if per_user:
        check = model_query(context, models.ProjectUserQuota).filter(
            models.ProjectUserQuota.project_id == project_id,
            models.ProjectUserQuota.user_id == user_id,
            models.ProjectUserQuota.resource == resource,
        ).all()
        quota_ref = models.ProjectUserQuota()
        quota_ref.user_id = user_id
    elif share_type_id:
        check = model_query(context, models.ProjectShareTypeQuota).filter(
            models.ProjectShareTypeQuota.project_id == project_id,
            models.ProjectShareTypeQuota.share_type_id == share_type_id,
            models.ProjectShareTypeQuota.resource == resource,
        ).all()
        quota_ref = models.ProjectShareTypeQuota()
        quota_ref.share_type_id = share_type_id
    else:
        check = model_query(context, models.Quota).filter(
            models.Quota.project_id == project_id,
            models.Quota.resource == resource,
        ).all()
        quota_ref = models.Quota()
    if check:
        raise exception.QuotaExists(project_id=project_id, resource=resource)

    quota_ref.project_id = project_id
    quota_ref.resource = resource
    quota_ref.hard_limit = limit
    session = get_session()
    with session.begin():
        quota_ref.save(session)
    return quota_ref


@require_admin_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def quota_update(context, project_id, resource, limit, user_id=None,
                 share_type_id=None):
    per_user = user_id and resource not in PER_PROJECT_QUOTAS
    if per_user:
        query = model_query(context, models.ProjectUserQuota).filter(
            models.ProjectUserQuota.project_id == project_id,
            models.ProjectUserQuota.user_id == user_id,
            models.ProjectUserQuota.resource == resource,
        )
    elif share_type_id:
        query = model_query(context, models.ProjectShareTypeQuota).filter(
            models.ProjectShareTypeQuota.project_id == project_id,
            models.ProjectShareTypeQuota.share_type_id == share_type_id,
            models.ProjectShareTypeQuota.resource == resource,
        )
    else:
        query = model_query(context, models.Quota).filter(
            models.Quota.project_id == project_id,
            models.Quota.resource == resource,
        )

    result = query.update({'hard_limit': limit})
    if not result:
        if per_user:
            raise exception.ProjectUserQuotaNotFound(
                project_id=project_id, user_id=user_id)
        elif share_type_id:
            raise exception.ProjectShareTypeQuotaNotFound(
                project_id=project_id, share_type=share_type_id)
        raise exception.ProjectQuotaNotFound(project_id=project_id)


###################


@require_context
def quota_class_get(context, class_name, resource, session=None):
    result = (model_query(context, models.QuotaClass, session=session,
                          read_deleted="no").
              filter_by(class_name=class_name).
              filter_by(resource=resource).
              first())

    if not result:
        raise exception.QuotaClassNotFound(class_name=class_name)

    return result


@require_context
def quota_class_get_default(context):
    rows = (model_query(context, models.QuotaClass, read_deleted="no").
            filter_by(class_name=_DEFAULT_QUOTA_NAME).
            all())

    result = {'class_name': _DEFAULT_QUOTA_NAME}
    for row in rows:
        result[row.resource] = row.hard_limit

    return result


@require_context
def quota_class_get_all_by_name(context, class_name):
    authorize_quota_class_context(context, class_name)

    rows = (model_query(context, models.QuotaClass, read_deleted="no").
            filter_by(class_name=class_name).
            all())

    result = {'class_name': class_name}
    for row in rows:
        result[row.resource] = row.hard_limit

    return result


@require_admin_context
def quota_class_create(context, class_name, resource, limit):
    quota_class_ref = models.QuotaClass()
    quota_class_ref.class_name = class_name
    quota_class_ref.resource = resource
    quota_class_ref.hard_limit = limit
    session = get_session()
    with session.begin():
        quota_class_ref.save(session)
    return quota_class_ref


@require_admin_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def quota_class_update(context, class_name, resource, limit):
    result = (model_query(context, models.QuotaClass, read_deleted="no").
              filter_by(class_name=class_name).
              filter_by(resource=resource).
              update({'hard_limit': limit}))

    if not result:
        raise exception.QuotaClassNotFound(class_name=class_name)


###################


@require_context
def quota_usage_get(context, project_id, resource, user_id=None,
                    share_type_id=None):
    query = (model_query(context, models.QuotaUsage, read_deleted="no").
             filter_by(project_id=project_id).
             filter_by(resource=resource))
    if user_id:
        if resource not in PER_PROJECT_QUOTAS:
            result = query.filter_by(user_id=user_id).first()
        else:
            result = query.filter_by(user_id=None).first()
    elif share_type_id:
        result = query.filter_by(queryshare_type_id=share_type_id).first()
    else:
        result = query.first()

    if not result:
        raise exception.QuotaUsageNotFound(project_id=project_id)

    return result


def _quota_usage_get_all(context, project_id, user_id=None,
                         share_type_id=None):
    authorize_project_context(context, project_id)
    query = (model_query(context, models.QuotaUsage, read_deleted="no").
             filter_by(project_id=project_id))
    result = {'project_id': project_id}
    if user_id:
        query = query.filter(or_(models.QuotaUsage.user_id == user_id,
                                 models.QuotaUsage.user_id is None))
        result['user_id'] = user_id
    elif share_type_id:
        query = query.filter_by(share_type_id=share_type_id)
        result['share_type_id'] = share_type_id
    else:
        query = query.filter_by(share_type_id=None)

    rows = query.all()
    for row in rows:
        if row.resource in result:
            result[row.resource]['in_use'] += row.in_use
            result[row.resource]['reserved'] += row.reserved
        else:
            result[row.resource] = dict(in_use=row.in_use,
                                        reserved=row.reserved)

    return result


@require_context
def quota_usage_get_all_by_project(context, project_id):
    return _quota_usage_get_all(context, project_id)


@require_context
def quota_usage_get_all_by_project_and_user(context, project_id, user_id):
    return _quota_usage_get_all(context, project_id, user_id=user_id)


@require_context
def quota_usage_get_all_by_project_and_share_type(context, project_id,
                                                  share_type_id):
    return _quota_usage_get_all(
        context, project_id, share_type_id=share_type_id)


def _quota_usage_create(context, project_id, user_id, resource, in_use,
                        reserved, until_refresh, share_type_id=None,
                        session=None):
    quota_usage_ref = models.QuotaUsage()
    if share_type_id:
        quota_usage_ref.share_type_id = share_type_id
    else:
        quota_usage_ref.user_id = user_id
    quota_usage_ref.project_id = project_id
    quota_usage_ref.resource = resource
    quota_usage_ref.in_use = in_use
    quota_usage_ref.reserved = reserved
    quota_usage_ref.until_refresh = until_refresh
    # updated_at is needed for judgement of max_age
    quota_usage_ref.updated_at = timeutils.utcnow()

    quota_usage_ref.save(session=session)

    return quota_usage_ref


@require_admin_context
def quota_usage_create(context, project_id, user_id, resource, in_use,
                       reserved, until_refresh, share_type_id=None):
    session = get_session()
    return _quota_usage_create(
        context, project_id, user_id, resource, in_use, reserved,
        until_refresh, share_type_id=share_type_id, session=session)


@require_admin_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def quota_usage_update(context, project_id, user_id, resource,
                       share_type_id=None, **kwargs):
    updates = {}
    for key in ('in_use', 'reserved', 'until_refresh'):
        if key in kwargs:
            updates[key] = kwargs[key]

    query = model_query(
        context, models.QuotaUsage, read_deleted="no",
    ).filter_by(project_id=project_id).filter_by(resource=resource)
    if share_type_id:
        query = query.filter_by(share_type_id=share_type_id)
    else:
        query = query.filter(or_(models.QuotaUsage.user_id == user_id,
                                 models.QuotaUsage.user_id is None))
    result = query.update(updates)

    if not result:
        raise exception.QuotaUsageNotFound(project_id=project_id)


###################


def _reservation_create(context, uuid, usage, project_id, user_id, resource,
                        delta, expire, share_type_id=None, session=None):
    reservation_ref = models.Reservation()
    reservation_ref.uuid = uuid
    reservation_ref.usage_id = usage['id']
    reservation_ref.project_id = project_id
    if share_type_id:
        reservation_ref.share_type_id = share_type_id
    else:
        reservation_ref.user_id = user_id
    reservation_ref.resource = resource
    reservation_ref.delta = delta
    reservation_ref.expire = expire
    reservation_ref.save(session=session)
    return reservation_ref


###################


# NOTE(johannes): The quota code uses SQL locking to ensure races don't
# cause under or over counting of resources. To avoid deadlocks, this
# code always acquires the lock on quota_usages before acquiring the lock
# on reservations.

def _get_share_type_quota_usages(context, session, project_id, share_type_id):
    rows = model_query(
        context, models.QuotaUsage, read_deleted="no", session=session,
    ).filter(
        models.QuotaUsage.project_id == project_id,
        models.QuotaUsage.share_type_id == share_type_id,
    ).with_lockmode('update').all()
    return {row.resource: row for row in rows}


def _get_user_quota_usages(context, session, project_id, user_id):
    # Broken out for testability
    rows = (model_query(context, models.QuotaUsage,
                        read_deleted="no",
                        session=session).
            filter_by(project_id=project_id).
            filter(or_(models.QuotaUsage.user_id == user_id,
                       models.QuotaUsage.user_id is None)).
            with_lockmode('update').
            all())
    return {row.resource: row for row in rows}


def _get_project_quota_usages(context, session, project_id):
    rows = (model_query(context, models.QuotaUsage,
                        read_deleted="no",
                        session=session).
            filter_by(project_id=project_id).
            filter(models.QuotaUsage.share_type_id is None).
            with_lockmode('update').
            all())
    result = dict()
    # Get the total count of in_use,reserved
    for row in rows:
        if row.resource in result:
            result[row.resource]['in_use'] += row.in_use
            result[row.resource]['reserved'] += row.reserved
            result[row.resource]['total'] += (row.in_use + row.reserved)
        else:
            result[row.resource] = dict(in_use=row.in_use,
                                        reserved=row.reserved,
                                        total=row.in_use + row.reserved)
    return result


@require_context
def quota_reserve(context, resources, project_quotas, user_quotas,
                  share_type_quotas, deltas, expire, until_refresh,
                  max_age, project_id=None, user_id=None, share_type_id=None):
    user_reservations = _quota_reserve(
        context, resources, project_quotas, user_quotas,
        deltas, expire, until_refresh, max_age, project_id, user_id=user_id)
    if share_type_id:
        try:
            st_reservations = _quota_reserve(
                context, resources, project_quotas, share_type_quotas,
                deltas, expire, until_refresh, max_age, project_id,
                share_type_id=share_type_id)
        except exception.OverQuota:
            with excutils.save_and_reraise_exception():
                # rollback previous reservations
                reservation_rollback(
                    context, user_reservations,
                    project_id=project_id, user_id=user_id)
        return user_reservations + st_reservations
    return user_reservations


@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def _quota_reserve(context, resources, project_quotas, user_or_st_quotas,
                   deltas, expire, until_refresh,
                   max_age, project_id=None, user_id=None, share_type_id=None):
    elevated = context.elevated()
    session = get_session()
    with session.begin():

        if project_id is None:
            project_id = context.project_id
        if share_type_id:
            user_or_st_usages = _get_share_type_quota_usages(
                context, session, project_id, share_type_id)
        else:
            user_id = user_id if user_id else context.user_id
            user_or_st_usages = _get_user_quota_usages(
                context, session, project_id, user_id)

        # Get the current usages
        project_usages = _get_project_quota_usages(
            context, session, project_id)

        # Handle usage refresh
        work = set(deltas.keys())
        while work:
            resource = work.pop()

            # Do we need to refresh the usage?
            refresh = False
            if ((resource not in PER_PROJECT_QUOTAS) and
                    (resource not in user_or_st_usages)):
                user_or_st_usages[resource] = _quota_usage_create(
                    elevated,
                    project_id,
                    user_id,
                    resource,
                    0, 0,
                    until_refresh or None,
                    share_type_id=share_type_id,
                    session=session)
                refresh = True
            elif ((resource in PER_PROJECT_QUOTAS) and
                    (resource not in user_or_st_usages)):
                user_or_st_usages[resource] = _quota_usage_create(
                    elevated,
                    project_id,
                    None,
                    resource,
                    0, 0,
                    until_refresh or None,
                    share_type_id=share_type_id,
                    session=session)
                refresh = True
            elif user_or_st_usages[resource].in_use < 0:
                # Negative in_use count indicates a desync, so try to
                # heal from that...
                refresh = True
            elif user_or_st_usages[resource].until_refresh is not None:
                user_or_st_usages[resource].until_refresh -= 1
                if user_or_st_usages[resource].until_refresh <= 0:
                    refresh = True
            elif max_age and (user_or_st_usages[resource].updated_at -
                              timeutils.utcnow()).seconds >= max_age:
                refresh = True

            # OK, refresh the usage
            if refresh:
                # Grab the sync routine
                sync = QUOTA_SYNC_FUNCTIONS[resources[resource].sync]

                updates = sync(
                    elevated, project_id, user_id,
                    share_type_id=share_type_id, session=session)
                for res, in_use in updates.items():
                    # Make sure we have a destination for the usage!
                    if ((res not in PER_PROJECT_QUOTAS) and
                            (res not in user_or_st_usages)):
                        user_or_st_usages[res] = _quota_usage_create(
                            elevated,
                            project_id,
                            user_id,
                            res,
                            0, 0,
                            until_refresh or None,
                            share_type_id=share_type_id,
                            session=session)
                    if ((res in PER_PROJECT_QUOTAS) and
                            (res not in user_or_st_usages)):
                        user_or_st_usages[res] = _quota_usage_create(
                            elevated,
                            project_id,
                            None,
                            res,
                            0, 0,
                            until_refresh or None,
                            share_type_id=share_type_id,
                            session=session)

                    if user_or_st_usages[res].in_use != in_use:
                        LOG.debug(
                            'quota_usages out of sync, updating. '
                            'project_id: %(project_id)s, '
                            'user_id: %(user_id)s, '
                            'share_type_id: %(share_type_id)s, '
                            'resource: %(res)s, '
                            'tracked usage: %(tracked_use)s, '
                            'actual usage: %(in_use)s',
                            {'project_id': project_id,
                             'user_id': user_id,
                             'share_type_id': share_type_id,
                             'res': res,
                             'tracked_use': user_or_st_usages[res].in_use,
                             'in_use': in_use})

                    # Update the usage
                    user_or_st_usages[res].in_use = in_use
                    user_or_st_usages[res].until_refresh = (
                        until_refresh or None)

                    # Because more than one resource may be refreshed
                    # by the call to the sync routine, and we don't
                    # want to double-sync, we make sure all refreshed
                    # resources are dropped from the work set.
                    work.discard(res)

                    # NOTE(Vek): We make the assumption that the sync
                    #            routine actually refreshes the
                    #            resources that it is the sync routine
                    #            for.  We don't check, because this is
                    #            a best-effort mechanism.

        # Check for deltas that would go negative
        unders = [res for res, delta in deltas.items()
                  if delta < 0 and
                  delta + user_or_st_usages[res].in_use < 0]

        # Now, let's check the quotas
        # NOTE(Vek): We're only concerned about positive increments.
        #            If a project has gone over quota, we want them to
        #            be able to reduce their usage without any
        #            problems.
        for key, value in user_or_st_usages.items():
            if key not in project_usages:
                project_usages[key] = value
        overs = [res for res, delta in deltas.items()
                 if user_or_st_quotas[res] >= 0 and delta >= 0 and
                 (project_quotas[res] < delta +
                  project_usages[res]['total'] or
                  user_or_st_quotas[res] < delta +
                  user_or_st_usages[res].total)]

        # NOTE(Vek): The quota check needs to be in the transaction,
        #            but the transaction doesn't fail just because
        #            we're over quota, so the OverQuota raise is
        #            outside the transaction.  If we did the raise
        #            here, our usage updates would be discarded, but
        #            they're not invalidated by being over-quota.

        # Create the reservations
        if not overs:
            reservations = []
            for res, delta in deltas.items():
                reservation = _reservation_create(elevated,
                                                  uuidutils.generate_uuid(),
                                                  user_or_st_usages[res],
                                                  project_id,
                                                  user_id,
                                                  res, delta, expire,
                                                  share_type_id=share_type_id,
                                                  session=session)
                reservations.append(reservation.uuid)

                # Also update the reserved quantity
                # NOTE(Vek): Again, we are only concerned here about
                #            positive increments.  Here, though, we're
                #            worried about the following scenario:
                #
                #            1) User initiates resize down.
                #            2) User allocates a new instance.
                #            3) Resize down fails or is reverted.
                #            4) User is now over quota.
                #
                #            To prevent this, we only update the
                #            reserved value if the delta is positive.
                if delta > 0:
                    user_or_st_usages[res].reserved += delta

        # Apply updates to the usages table
        for usage_ref in user_or_st_usages.values():
            session.add(usage_ref)

    if unders:
        LOG.warning("Change will make usage less than 0 for the following "
                    "resources: %s", unders)
    if overs:
        if project_quotas == user_or_st_quotas:
            usages = project_usages
        else:
            usages = user_or_st_usages
        usages = {k: dict(in_use=v['in_use'], reserved=v['reserved'])
                  for k, v in usages.items()}
        raise exception.OverQuota(
            overs=sorted(overs), quotas=user_or_st_quotas, usages=usages)

    return reservations


def _quota_reservations_query(session, context, reservations):
    """Return the relevant reservations."""

    # Get the listed reservations
    return (model_query(context, models.Reservation,
                        read_deleted="no",
                        session=session).
            filter(models.Reservation.uuid.in_(reservations)).
            with_lockmode('update'))


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def reservation_commit(context, reservations, project_id=None, user_id=None,
                       share_type_id=None):
    session = get_session()
    with session.begin():
        if share_type_id:
            st_usages = _get_share_type_quota_usages(
                context, session, project_id, share_type_id)
        else:
            st_usages = {}
        user_usages = _get_user_quota_usages(
            context, session, project_id, user_id)

        reservation_query = _quota_reservations_query(
            session, context, reservations)
        for reservation in reservation_query.all():
            if reservation['share_type_id']:
                usages = st_usages
            else:
                usages = user_usages
            usage = usages[reservation.resource]
            if reservation.delta >= 0:
                usage.reserved -= reservation.delta
            usage.in_use += reservation.delta
        reservation_query.soft_delete(synchronize_session=False)


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def reservation_rollback(context, reservations, project_id=None, user_id=None,
                         share_type_id=None):
    session = get_session()
    with session.begin():
        if share_type_id:
            st_usages = _get_share_type_quota_usages(
                context, session, project_id, share_type_id)
        else:
            st_usages = {}
        user_usages = _get_user_quota_usages(
            context, session, project_id, user_id)

        reservation_query = _quota_reservations_query(
            session, context, reservations)
        for reservation in reservation_query.all():
            if reservation['share_type_id']:
                usages = st_usages
            else:
                usages = user_usages
            usage = usages[reservation.resource]
            if reservation.delta >= 0:
                usage.reserved -= reservation.delta
        reservation_query.soft_delete(synchronize_session=False)


@require_admin_context
def quota_destroy_all_by_project_and_user(context, project_id, user_id):
    session = get_session()
    with session.begin():
        (model_query(context, models.ProjectUserQuota, session=session,
                     read_deleted="no").
         filter_by(project_id=project_id).
         filter_by(user_id=user_id).soft_delete(synchronize_session=False))

        (model_query(context, models.QuotaUsage,
                     session=session, read_deleted="no").
         filter_by(project_id=project_id).
         filter_by(user_id=user_id).soft_delete(synchronize_session=False))

        (model_query(context, models.Reservation,
                     session=session, read_deleted="no").
         filter_by(project_id=project_id).
         filter_by(user_id=user_id).soft_delete(synchronize_session=False))


@require_admin_context
def quota_destroy_all_by_share_type(context, share_type_id, project_id=None):
    """Soft deletes all quotas, usages and reservations.

    :param context: request context for queries, updates and logging
    :param share_type_id: ID of the share type to filter the quotas, usages
        and reservations under.
    :param project_id: ID of the project to filter the quotas, usages and
        reservations under. If not provided, share type quotas for all
        projects will be acted upon.
    """
    session = get_session()
    with session.begin():
        share_type_quotas = model_query(
            context, models.ProjectShareTypeQuota, session=session,
            read_deleted="no",
        ).filter_by(share_type_id=share_type_id)

        share_type_quota_usages = model_query(
            context, models.QuotaUsage, session=session, read_deleted="no",
        ).filter_by(share_type_id=share_type_id)

        share_type_quota_reservations = model_query(
            context, models.Reservation, session=session, read_deleted="no",
        ).filter_by(share_type_id=share_type_id)

        if project_id is not None:
            share_type_quotas = share_type_quotas.filter_by(
                project_id=project_id)
            share_type_quota_usages = share_type_quota_usages.filter_by(
                project_id=project_id)
            share_type_quota_reservations = (
                share_type_quota_reservations.filter_by(project_id=project_id))

        share_type_quotas.soft_delete(synchronize_session=False)
        share_type_quota_usages.soft_delete(synchronize_session=False)
        share_type_quota_reservations.soft_delete(synchronize_session=False)


@require_admin_context
def quota_destroy_all_by_project(context, project_id):
    session = get_session()
    with session.begin():
        (model_query(context, models.Quota, session=session,
                     read_deleted="no").
         filter_by(project_id=project_id).
         soft_delete(synchronize_session=False))

        (model_query(context, models.ProjectUserQuota, session=session,
                     read_deleted="no").
         filter_by(project_id=project_id).
         soft_delete(synchronize_session=False))

        (model_query(context, models.QuotaUsage,
                     session=session, read_deleted="no").
         filter_by(project_id=project_id).
         soft_delete(synchronize_session=False))

        (model_query(context, models.Reservation,
                     session=session, read_deleted="no").
         filter_by(project_id=project_id).
         soft_delete(synchronize_session=False))


@require_admin_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def reservation_expire(context):
    session = get_session()
    with session.begin():
        current_time = timeutils.utcnow()
        reservation_query = (model_query(
            context, models.Reservation,
            session=session, read_deleted="no").
            filter(models.Reservation.expire < current_time))

        for reservation in reservation_query.all():
            if reservation.delta >= 0:
                quota_usage = model_query(context, models.QuotaUsage,
                                          session=session,
                                          read_deleted="no").filter(
                    models.QuotaUsage.id == reservation.usage_id).first()
                quota_usage.reserved -= reservation.delta
                session.add(quota_usage)

        reservation_query.soft_delete(synchronize_session=False)


################

def _extract_subdict_by_fields(source_dict, fields):
    dict_to_extract_from = copy.deepcopy(source_dict)
    sub_dict = {}
    for field in fields:
        field_value = dict_to_extract_from.pop(field, None)
        if field_value:
            sub_dict.update({field: field_value})

    return sub_dict, dict_to_extract_from


def _extract_share_instance_values(values):
    share_instance_model_fields = [
        'status', 'host', 'scheduled_at', 'launched_at', 'terminated_at',
        'share_server_id', 'share_network_id', 'availability_zone',
        'replica_state', 'share_type_id', 'share_type', 'access_rules_status',
    ]
    share_instance_values, share_values = (
        _extract_subdict_by_fields(values, share_instance_model_fields)
    )
    return share_instance_values, share_values


def _extract_snapshot_instance_values(values):
    fields = ['status', 'progress', 'provider_location']
    snapshot_instance_values, snapshot_values = (
        _extract_subdict_by_fields(values, fields)
    )
    return snapshot_instance_values, snapshot_values


################


@require_context
def share_instance_create(context, share_id, values):
    session = get_session()
    with session.begin():
        return _share_instance_create(context, share_id, values, session)


def _share_instance_create(context, share_id, values, session):
    if not values.get('id'):
        values['id'] = uuidutils.generate_uuid()
    values.update({'share_id': share_id})

    share_instance_ref = models.ShareInstance()
    share_instance_ref.update(values)
    share_instance_ref.save(session=session)

    return share_instance_get(context, share_instance_ref['id'],
                              session=session)


@require_context
def share_instance_update(context, share_instance_id, values,
                          with_share_data=False):
    session = get_session()
    _ensure_availability_zone_exists(context, values, session, strict=False)
    with session.begin():
        instance_ref = _share_instance_update(
            context, share_instance_id, values, session
        )
        if with_share_data:
            parent_share = share_get(context, instance_ref['share_id'],
                                     session=session)
            instance_ref.set_share_data(parent_share)
        return instance_ref


def _share_instance_update(context, share_instance_id, values, session):
    share_instance_ref = share_instance_get(context, share_instance_id,
                                            session=session)
    share_instance_ref.update(values)
    share_instance_ref.save(session=session)
    return share_instance_ref


@require_context
def share_instance_get(context, share_instance_id, session=None,
                       with_share_data=False):
    if session is None:
        session = get_session()
    result = model_query(
        context, models.ShareInstance, session=session,
    ).filter_by(
        id=share_instance_id,
    ).options(
        joinedload('export_locations'),
        joinedload('share_type'),
    ).first()
    if result is None:
        raise exception.NotFound()

    if with_share_data:
        parent_share = share_get(context, result['share_id'], session=session)
        result.set_share_data(parent_share)

    return result


@require_admin_context
def share_instances_get_all(context, filters=None):
    session = get_session()
    query = model_query(
        context, models.ShareInstance, session=session, read_deleted="no",
    ).options(
        joinedload('export_locations'),
    )

    filters = filters or {}

    export_location_id = filters.get('export_location_id')
    export_location_path = filters.get('export_location_path')
    if export_location_id or export_location_path:
        query = query.join(
            models.ShareInstanceExportLocations,
            models.ShareInstanceExportLocations.share_instance_id ==
            models.ShareInstance.id)
        if export_location_path:
            query = query.filter(
                models.ShareInstanceExportLocations.path ==
                export_location_path)
        if export_location_id:
            query = query.filter(
                models.ShareInstanceExportLocations.uuid ==
                export_location_id)

    # Returns list of share instances that satisfy filters.
    query = query.all()
    return query


@require_context
def share_instance_delete(context, instance_id, session=None,
                          need_to_update_usages=False):
    if session is None:
        session = get_session()

    with session.begin():
        share_export_locations_update(context, instance_id, [], delete=True)
        instance_ref = share_instance_get(context, instance_id,
                                          session=session)
        instance_ref.soft_delete(session=session, update_status=True)
        share = share_get(context, instance_ref['share_id'], session=session)
        if len(share.instances) == 0:
            share_access_delete_all_by_share(context, share['id'])
            session.query(models.ShareMetadata).filter_by(
                share_id=share['id']).soft_delete()
            share.soft_delete(session=session)

            if need_to_update_usages:
                reservations = None
                try:
                    # we give the user_id of the share, to update
                    # the quota usage for the user, who created the share
                    reservations = QUOTAS.reserve(
                        context,
                        project_id=share['project_id'],
                        shares=-1,
                        gigabytes=-share['size'],
                        user_id=share['user_id'],
                        share_type_id=instance_ref['share_type_id'])
                    QUOTAS.commit(
                        context, reservations, project_id=share['project_id'],
                        user_id=share['user_id'],
                        share_type_id=instance_ref['share_type_id'])
                except Exception:
                    LOG.exception(
                        "Failed to update usages deleting share '%s'.",
                        share["id"])
                    if reservations:
                        QUOTAS.rollback(
                            context, reservations,
                            share_type_id=instance_ref['share_type_id'])


def _set_instances_share_data(context, instances, session):
    if instances and not isinstance(instances, list):
        instances = [instances]

    instances_with_share_data = []
    for instance in instances:
        try:
            parent_share = share_get(context, instance['share_id'],
                                     session=session)
        except exception.NotFound:
            continue
        instance.set_share_data(parent_share)
        instances_with_share_data.append(instance)
    return instances_with_share_data


@require_admin_context
def share_instances_get_all_by_host(context, host, with_share_data=False,
                                    session=None):
    """Retrieves all share instances hosted on a host."""
    session = session or get_session()
    instances = (
        model_query(context, models.ShareInstance).filter(
            or_(
                models.ShareInstance.host == host,
                models.ShareInstance.host.like("{0}#%".format(host))
            )
        ).all()
    )

    if with_share_data:
        instances = _set_instances_share_data(context, instances, session)
    return instances


@require_context
def share_instances_get_all_by_share_network(context, share_network_id):
    """Returns list of share instances that belong to given share network."""
    result = (
        model_query(context, models.ShareInstance).filter(
            models.ShareInstance.share_network_id == share_network_id,
        ).all()
    )
    return result


@require_context
def share_instances_get_all_by_share_server(context, share_server_id):
    """Returns list of share instance with given share server."""
    result = (
        model_query(context, models.ShareInstance).filter(
            models.ShareInstance.share_server_id == share_server_id,
        ).all()
    )
    return result


@require_context
def share_instances_get_all_by_share(context, share_id):
    """Returns list of share instances that belong to given share."""
    result = (
        model_query(context, models.ShareInstance).filter(
            models.ShareInstance.share_id == share_id,
        ).all()
    )
    return result


@require_context
def share_instances_get_all_by_share_group_id(context, share_group_id):
    """Returns list of share instances that belong to given share group."""
    result = (
        model_query(context, models.Share).filter(
            models.Share.share_group_id == share_group_id,
        ).all()
    )
    instances = []
    for share in result:
        instance = share.instance
        instance.set_share_data(share)
        instances.append(instance)

    return instances


################

def _share_replica_get_with_filters(context, share_id=None, replica_id=None,
                                    replica_state=None, status=None,
                                    with_share_server=True, session=None):

    query = model_query(context, models.ShareInstance, session=session,
                        read_deleted="no")

    if share_id is not None:
        query = query.filter(models.ShareInstance.share_id == share_id)

    if replica_id is not None:
        query = query.filter(models.ShareInstance.id == replica_id)

    if replica_state is not None:
        query = query.filter(
            models.ShareInstance.replica_state == replica_state)
    else:
        query = query.filter(models.ShareInstance.replica_state.isnot(None))

    if status is not None:
        query = query.filter(models.ShareInstance.status == status)

    if with_share_server:
        query = query.options(joinedload('share_server'))

    return query


def _set_replica_share_data(context, replicas, session):
    if replicas and not isinstance(replicas, list):
        replicas = [replicas]

    for replica in replicas:
        parent_share = share_get(context, replica['share_id'], session=session)
        replica.set_share_data(parent_share)

    return replicas


@require_context
def share_replicas_get_all(context, with_share_data=False,
                           with_share_server=True, session=None):
    """Returns replica instances for all available replicated shares."""
    session = session or get_session()

    result = _share_replica_get_with_filters(
        context, with_share_server=with_share_server, session=session).all()

    if with_share_data:
        result = _set_replica_share_data(context, result, session)

    return result


@require_context
def share_replicas_get_all_by_share(context, share_id,
                                    with_share_data=False,
                                    with_share_server=False, session=None):
    """Returns replica instances for a given share."""
    session = session or get_session()

    result = _share_replica_get_with_filters(
        context, with_share_server=with_share_server,
        share_id=share_id, session=session).all()

    if with_share_data:
        result = _set_replica_share_data(context, result, session)

    return result


@require_context
def share_replicas_get_available_active_replica(context, share_id,
                                                with_share_data=False,
                                                with_share_server=False,
                                                session=None):
    """Returns an 'active' replica instance that is 'available'."""
    session = session or get_session()

    result = _share_replica_get_with_filters(
        context, with_share_server=with_share_server, share_id=share_id,
        replica_state=constants.REPLICA_STATE_ACTIVE,
        status=constants.STATUS_AVAILABLE, session=session).first()

    if result and with_share_data:
        result = _set_replica_share_data(context, result, session)[0]

    return result


@require_context
def share_replica_get(context, replica_id, with_share_data=False,
                      with_share_server=False, session=None):
    """Returns summary of requested replica if available."""
    session = session or get_session()

    result = _share_replica_get_with_filters(
        context, with_share_server=with_share_server,
        replica_id=replica_id, session=session).first()

    if result is None:
        raise exception.ShareReplicaNotFound(replica_id=replica_id)

    if with_share_data:
        result = _set_replica_share_data(context, result, session)[0]

    return result


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def share_replica_update(context, share_replica_id, values,
                         with_share_data=False, session=None):
    """Updates a share replica with specified values."""
    session = session or get_session()

    with session.begin():
        _ensure_availability_zone_exists(context, values, session,
                                         strict=False)
        updated_share_replica = _share_instance_update(
            context, share_replica_id, values, session=session)

        if with_share_data:
            updated_share_replica = _set_replica_share_data(
                context, updated_share_replica, session)[0]

    return updated_share_replica


@require_context
def share_replica_delete(context, share_replica_id, session=None):
    """Deletes a share replica."""
    session = session or get_session()

    share_instance_delete(context, share_replica_id, session=session)


################


def _share_get_query(context, session=None):
    if session is None:
        session = get_session()
    return (model_query(context, models.Share, session=session).
            options(joinedload('share_metadata')))


def _metadata_refs(metadata_dict, meta_class):
    metadata_refs = []
    if metadata_dict:
        for k, v in metadata_dict.items():
            value = six.text_type(v) if isinstance(v, bool) else v

            metadata_ref = meta_class()
            metadata_ref['key'] = k
            metadata_ref['value'] = value
            metadata_refs.append(metadata_ref)
    return metadata_refs


@require_context
def share_create(context, share_values, create_share_instance=True):
    values = copy.deepcopy(share_values)
    values = ensure_model_dict_has_id(values)
    values['share_metadata'] = _metadata_refs(values.get('metadata'),
                                              models.ShareMetadata)
    session = get_session()
    share_ref = models.Share()
    share_instance_values, share_values = _extract_share_instance_values(
        values)
    _ensure_availability_zone_exists(context, share_instance_values, session,
                                     strict=False)
    share_ref.update(share_values)

    with session.begin():
        share_ref.save(session=session)

        if create_share_instance:
            _share_instance_create(context, share_ref['id'],
                                   share_instance_values, session=session)

        # NOTE(u_glide): Do so to prevent errors with relationships
        return share_get(context, share_ref['id'], session=session)


@require_admin_context
def share_data_get_for_project(context, project_id, user_id,
                               share_type_id=None, session=None):
    query = (model_query(context, models.Share,
                         func.count(models.Share.id),
                         func.sum(models.Share.size),
                         read_deleted="no",
                         session=session).
             filter_by(project_id=project_id))
    if share_type_id:
        query = query.join("instances").filter_by(share_type_id=share_type_id)
    elif user_id:
        query = query.filter_by(user_id=user_id)
    result = query.first()
    return (result[0] or 0, result[1] or 0)


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def share_update(context, share_id, update_values):
    session = get_session()
    values = copy.deepcopy(update_values)

    share_instance_values, share_values = _extract_share_instance_values(
        values)
    _ensure_availability_zone_exists(context, share_instance_values, session,
                                     strict=False)

    with session.begin():
        share_ref = share_get(context, share_id, session=session)

        _share_instance_update(context, share_ref.instance['id'],
                               share_instance_values, session=session)

        share_ref.update(share_values)
        share_ref.save(session=session)
        return share_ref


@require_context
def share_get(context, share_id, session=None):
    result = _share_get_query(context, session).filter_by(id=share_id).first()

    if result is None:
        raise exception.NotFound()

    return result


def _share_get_all_with_filters(context, project_id=None, share_server_id=None,
                                share_group_id=None, filters=None,
                                is_public=False, sort_key=None,
                                sort_dir=None):
    """Returns sorted list of shares that satisfies filters.

    :param context: context to query under
    :param project_id: project id that owns shares
    :param share_server_id: share server that hosts shares
    :param filters: dict of filters to specify share selection
    :param is_public: public shares from other projects will be added
                      to result if True
    :param sort_key: key of models.Share to be used for sorting
    :param sort_dir: desired direction of sorting, can be 'asc' and 'desc'
    :returns: list -- models.Share
    :raises: exception.InvalidInput
    """
    if not sort_key:
        sort_key = 'created_at'
    if not sort_dir:
        sort_dir = 'desc'
    query = (
        _share_get_query(context).join(
            models.ShareInstance,
            models.ShareInstance.share_id == models.Share.id
        )
    )

    if project_id:
        if is_public:
            query = query.filter(or_(models.Share.project_id == project_id,
                                     models.Share.is_public))
        else:
            query = query.filter(models.Share.project_id == project_id)
    if share_server_id:
        query = query.filter(
            models.ShareInstance.share_server_id == share_server_id)

    if share_group_id:
        query = query.filter(
            models.Share.share_group_id == share_group_id)

    # Apply filters
    if not filters:
        filters = {}

    export_location_id = filters.get('export_location_id')
    export_location_path = filters.get('export_location_path')
    if export_location_id or export_location_path:
        query = query.join(
            models.ShareInstanceExportLocations,
            models.ShareInstanceExportLocations.share_instance_id ==
            models.ShareInstance.id)
        if export_location_path:
            query = query.filter(
                models.ShareInstanceExportLocations.path ==
                export_location_path)
        if export_location_id:
            query = query.filter(
                models.ShareInstanceExportLocations.uuid ==
                export_location_id)

    if 'metadata' in filters:
        for k, v in filters['metadata'].items():
            query = query.filter(
                or_(models.Share.share_metadata.any(  # pylint: disable=E1101
                    key=k, value=v)))
    if 'extra_specs' in filters:
        query = query.join(
            models.ShareTypeExtraSpecs,
            models.ShareTypeExtraSpecs.share_type_id ==
            models.ShareInstance.share_type_id)
        for k, v in filters['extra_specs'].items():
            query = query.filter(or_(models.ShareTypeExtraSpecs.key == k,
                                     models.ShareTypeExtraSpecs.value == v))

    try:
        query = apply_sorting(models.Share, query, sort_key, sort_dir)
    except AttributeError:
        try:
            query = apply_sorting(
                models.ShareInstance, query, sort_key, sort_dir)
        except AttributeError:
            msg = _("Wrong sorting key provided - '%s'.") % sort_key
            raise exception.InvalidInput(reason=msg)

    # Returns list of shares that satisfy filters.
    query = query.all()
    return query


@require_admin_context
def share_get_all(context, filters=None, sort_key=None, sort_dir=None):
    query = _share_get_all_with_filters(
        context, filters=filters, sort_key=sort_key, sort_dir=sort_dir)
    return query


@require_context
def share_get_all_by_project(context, project_id, filters=None,
                             is_public=False, sort_key=None, sort_dir=None):
    """Returns list of shares with given project ID."""
    query = _share_get_all_with_filters(
        context, project_id=project_id, filters=filters, is_public=is_public,
        sort_key=sort_key, sort_dir=sort_dir,
    )
    return query


@require_context
def share_get_all_by_share_group_id(context, share_group_id,
                                    filters=None, sort_key=None,
                                    sort_dir=None):
    """Returns list of shares with given group ID."""
    query = _share_get_all_with_filters(
        context, share_group_id=share_group_id,
        filters=filters, sort_key=sort_key, sort_dir=sort_dir,
    )
    return query


@require_context
def share_get_all_by_share_server(context, share_server_id, filters=None,
                                  sort_key=None, sort_dir=None):
    """Returns list of shares with given share server."""
    query = _share_get_all_with_filters(
        context, share_server_id=share_server_id, filters=filters,
        sort_key=sort_key, sort_dir=sort_dir,
    )
    return query


@require_context
def share_delete(context, share_id):
    session = get_session()

    with session.begin():
        share_ref = share_get(context, share_id, session)

        if len(share_ref.instances) > 0:
            msg = _("Share %(id)s has %(count)s share instances.") % {
                'id': share_id, 'count': len(share_ref.instances)}
            raise exception.InvalidShare(msg)

        share_ref.soft_delete(session=session)

        (session.query(models.ShareMetadata).
            filter_by(share_id=share_id).soft_delete())


###################


def _share_access_get_query(context, session, values, read_deleted='no'):
    """Get access record."""
    query = model_query(context, models.ShareAccessMapping, session=session,
                        read_deleted=read_deleted)
    return query.filter_by(**values)


def _share_instance_access_query(context, session, access_id=None,
                                 instance_id=None):
    filters = {'deleted': 'False'}

    if access_id is not None:
        filters.update({'access_id': access_id})

    if instance_id is not None:
        filters.update({'share_instance_id': instance_id})

    return model_query(context, models.ShareInstanceAccessMapping,
                       session=session).filter_by(**filters)


@require_context
def share_access_create(context, values):
    values = ensure_model_dict_has_id(values)
    session = get_session()
    with session.begin():
        access_ref = models.ShareAccessMapping()
        access_ref.update(values)
        access_ref.save(session=session)

        parent_share = share_get(context, values['share_id'], session=session)

        for instance in parent_share.instances:
            vals = {
                'share_instance_id': instance['id'],
                'access_id': access_ref['id'],
            }

            _share_instance_access_create(vals, session)

    return share_access_get(context, access_ref['id'])


@require_context
def share_instance_access_create(context, values, share_instance_id):
    values = ensure_model_dict_has_id(values)
    session = get_session()
    with session.begin():
        access_list = _share_access_get_query(
            context, session, {
                'share_id': values['share_id'],
                'access_type': values['access_type'],
                'access_to': values['access_to'],
            }).all()
        if len(access_list) > 0:
            access_ref = access_list[0]
        else:
            access_ref = models.ShareAccessMapping()
        access_ref.update(values)
        access_ref.save(session=session)

        vals = {
            'share_instance_id': share_instance_id,
            'access_id': access_ref['id'],
        }

        _share_instance_access_create(vals, session)

    return share_access_get(context, access_ref['id'])


@require_context
def share_instance_access_copy(context, share_id, instance_id, session=None):
    """Copy access rules from share to share instance."""
    session = session or get_session()

    share_access_rules = _share_access_get_query(
        context, session, {'share_id': share_id}).all()

    for access_rule in share_access_rules:
        values = {
            'share_instance_id': instance_id,
            'access_id': access_rule['id'],
        }

        _share_instance_access_create(values, session)

    return share_access_rules


def _share_instance_access_create(values, session):
    access_ref = models.ShareInstanceAccessMapping()
    access_ref.update(ensure_model_dict_has_id(values))
    access_ref.save(session=session)
    return access_ref


@require_context
def share_access_get(context, access_id, session=None):
    """Get access record."""
    session = session or get_session()

    access = _share_access_get_query(
        context, session, {'id': access_id}).first()
    if access:
        return access
    else:
        raise exception.NotFound()


@require_context
def share_instance_access_get(context, access_id, instance_id,
                              with_share_access_data=True):
    """Get access record."""
    session = get_session()

    access = _share_instance_access_query(context, session, access_id,
                                          instance_id).first()
    if access is None:
        raise exception.NotFound()

    if with_share_access_data:
        access = _set_instances_share_access_data(context, access, session)[0]

    return access


@require_context
def share_access_get_all_for_share(context, share_id, session=None):
    session = session or get_session()
    return _share_access_get_query(
        context, session, {'share_id': share_id}).filter(
        models.ShareAccessMapping.instance_mappings.any()).all()


@require_context
def share_access_get_all_for_instance(context, instance_id, filters=None,
                                      with_share_access_data=True,
                                      session=None):
    """Get all access rules related to a certain share instance."""
    session = session or get_session()
    filters = copy.deepcopy(filters) if filters else {}
    filters.update({'share_instance_id': instance_id})
    legal_filter_keys = ('id', 'share_instance_id', 'access_id', 'state')
    query = _share_instance_access_query(context, session)

    query = exact_filter(
        query, models.ShareInstanceAccessMapping, filters, legal_filter_keys)

    instance_accesses = query.all()

    if with_share_access_data:
        instance_accesses = _set_instances_share_access_data(
            context, instance_accesses, session)

    return instance_accesses


def _set_instances_share_access_data(context, instance_accesses, session):
    if instance_accesses and not isinstance(instance_accesses, list):
        instance_accesses = [instance_accesses]

    for instance_access in instance_accesses:
        share_access = share_access_get(
            context, instance_access['access_id'], session=session)
        instance_access.set_share_access_data(share_access)

    return instance_accesses


def _set_instances_snapshot_access_data(context, instance_accesses, session):
    if instance_accesses and not isinstance(instance_accesses, list):
        instance_accesses = [instance_accesses]

    for instance_access in instance_accesses:
        snapshot_access = share_snapshot_access_get(
            context, instance_access['access_id'], session=session)
        instance_access.set_snapshot_access_data(snapshot_access)

    return instance_accesses


@require_context
def share_access_get_all_by_type_and_access(context, share_id, access_type,
                                            access):
    session = get_session()
    return _share_access_get_query(context, session,
                                   {'share_id': share_id,
                                    'access_type': access_type,
                                    'access_to': access}).all()


@require_context
def share_access_check_for_existing_access(context, share_id, access_type,
                                           access_to):
    return _check_for_existing_access(
        context, 'share', share_id, access_type, access_to)


def _check_for_existing_access(context, resource, resource_id, access_type,
                               access_to):

    session = get_session()
    if resource == 'share':
        query_method = _share_access_get_query
        access_to_field = models.ShareAccessMapping.access_to
    else:
        query_method = _share_snapshot_access_get_query
        access_to_field = models.ShareSnapshotAccessMapping.access_to

    with session.begin():
        if access_type == 'ip':
            rules = query_method(
                context, session, {'%s_id' % resource: resource_id,
                                   'access_type': access_type}).filter(
                access_to_field.startswith(access_to.split('/')[0])).all()

            matching_rules = [
                rule for rule in rules if
                ipaddress.ip_network(six.text_type(access_to)) ==
                ipaddress.ip_network(six.text_type(rule['access_to']))
            ]
            return len(matching_rules) > 0
        else:
            return query_method(
                context, session, {'%s_id' % resource: resource_id,
                                   'access_type': access_type,
                                   'access_to': access_to}).count() > 0


@require_context
def share_access_delete_all_by_share(context, share_id):
    session = get_session()
    with session.begin():
        (session.query(models.ShareAccessMapping).
            filter_by(share_id=share_id).soft_delete())


@require_context
def share_instance_access_delete(context, mapping_id):
    session = get_session()
    with session.begin():

        mapping = (session.query(models.ShareInstanceAccessMapping).
                   filter_by(id=mapping_id).first())

        if not mapping:
            exception.NotFound()

        mapping.soft_delete(session, update_status=True,
                            status_field_name='state')

        other_mappings = _share_instance_access_query(
            context, session, mapping['access_id']).all()

        # NOTE(u_glide): Remove access rule if all mappings were removed.
        if len(other_mappings) == 0:
            (
                session.query(models.ShareAccessMapping)
                .filter_by(id=mapping['access_id'])
                .soft_delete()
            )


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def share_instance_access_update(context, access_id, instance_id, updates):
    session = get_session()
    share_access_fields = ('access_type', 'access_to', 'access_key',
                           'access_level')

    share_access_map_updates, share_instance_access_map_updates = (
        _extract_subdict_by_fields(updates, share_access_fields)
    )

    with session.begin():
        share_access = _share_access_get_query(
            context, session, {'id': access_id}).first()
        share_access.update(share_access_map_updates)
        share_access.save(session=session)

        access = _share_instance_access_query(
            context, session, access_id, instance_id).first()
        access.update(share_instance_access_map_updates)
        access.save(session=session)

        return access

###################


@require_context
def share_snapshot_instance_create(context, snapshot_id, values, session=None):
    session = session or get_session()
    values = copy.deepcopy(values)

    if not values.get('id'):
        values['id'] = uuidutils.generate_uuid()
    values.update({'snapshot_id': snapshot_id})

    instance_ref = models.ShareSnapshotInstance()
    instance_ref.update(values)
    instance_ref.save(session=session)

    return share_snapshot_instance_get(context, instance_ref['id'],
                                       session=session)


@require_context
def share_snapshot_instance_update(context, instance_id, values):
    session = get_session()
    instance_ref = share_snapshot_instance_get(context, instance_id,
                                               session=session)

    # NOTE(u_glide): Ignore updates to custom properties
    for extra_key in models.ShareSnapshotInstance._extra_keys:
        if extra_key in values:
            values.pop(extra_key)

    instance_ref.update(values)
    instance_ref.save(session=session)
    return instance_ref


@require_context
def share_snapshot_instance_delete(context, snapshot_instance_id,
                                   session=None):
    session = session or get_session()

    with session.begin():

        snapshot_instance_ref = share_snapshot_instance_get(
            context, snapshot_instance_id, session=session)

        access_rules = share_snapshot_access_get_all_for_snapshot_instance(
            context, snapshot_instance_id, session=session)
        for rule in access_rules:
            share_snapshot_instance_access_delete(
                context, rule['access_id'], snapshot_instance_id)

        for el in snapshot_instance_ref.export_locations:
            share_snapshot_instance_export_location_delete(context, el['id'])

        snapshot_instance_ref.soft_delete(
            session=session, update_status=True)
        snapshot = share_snapshot_get(
            context, snapshot_instance_ref['snapshot_id'], session=session)
        if len(snapshot.instances) == 0:
            snapshot.soft_delete(session=session)


@require_context
def share_snapshot_instance_get(context, snapshot_instance_id, session=None,
                                with_share_data=False):

    session = session or get_session()

    result = _share_snapshot_instance_get_with_filters(
        context, instance_ids=[snapshot_instance_id], session=session).first()

    if result is None:
        raise exception.ShareSnapshotInstanceNotFound(
            instance_id=snapshot_instance_id)

    if with_share_data:
        result = _set_share_snapshot_instance_data(context, result, session)[0]

    return result


@require_context
def share_snapshot_instance_get_all_with_filters(context, search_filters,
                                                 with_share_data=False,
                                                 session=None):
    """Get snapshot instances filtered by known attrs, ignore unknown attrs.

    All filters accept list/tuples to filter on, along with simple values.
    """
    def listify(values):
        if values:
            if not isinstance(values, (list, tuple, set)):
                return values,
            else:
                return values

    session = session or get_session()
    _known_filters = ('instance_ids', 'snapshot_ids', 'share_instance_ids',
                      'statuses')

    filters = {k: listify(search_filters.get(k)) for k in _known_filters}

    result = _share_snapshot_instance_get_with_filters(
        context, session=session, **filters).all()

    if with_share_data:
        result = _set_share_snapshot_instance_data(context, result, session)

    return result


def _share_snapshot_instance_get_with_filters(context, instance_ids=None,
                                              snapshot_ids=None, statuses=None,
                                              share_instance_ids=None,
                                              session=None):

    query = model_query(context, models.ShareSnapshotInstance, session=session,
                        read_deleted="no")

    if instance_ids is not None:
        query = query.filter(
            models.ShareSnapshotInstance.id.in_(instance_ids))

    if snapshot_ids is not None:
        query = query.filter(
            models.ShareSnapshotInstance.snapshot_id.in_(snapshot_ids))

    if share_instance_ids is not None:
        query = query.filter(models.ShareSnapshotInstance.share_instance_id
                             .in_(share_instance_ids))

    if statuses is not None:
        query = query.filter(models.ShareSnapshotInstance.status.in_(statuses))

    query = query.options(joinedload('share_group_snapshot'))
    return query


def _set_share_snapshot_instance_data(context, snapshot_instances, session):
    if snapshot_instances and not isinstance(snapshot_instances, list):
        snapshot_instances = [snapshot_instances]

    for snapshot_instance in snapshot_instances:
        share_instance = share_instance_get(
            context, snapshot_instance['share_instance_id'], session=session,
            with_share_data=True)
        snapshot_instance['share'] = share_instance

    return snapshot_instances


###################


@require_context
def share_snapshot_create(context, create_values,
                          create_snapshot_instance=True):
    values = copy.deepcopy(create_values)
    values = ensure_model_dict_has_id(values)

    snapshot_ref = models.ShareSnapshot()
    snapshot_instance_values, snapshot_values = (
        _extract_snapshot_instance_values(values)
    )
    share_ref = share_get(context, snapshot_values.get('share_id'))
    snapshot_instance_values.update(
        {'share_instance_id': share_ref.instance.id}
    )

    snapshot_ref.update(snapshot_values)
    session = get_session()
    with session.begin():
        snapshot_ref.save(session=session)

        if create_snapshot_instance:
            share_snapshot_instance_create(
                context,
                snapshot_ref['id'],
                snapshot_instance_values,
                session=session
            )
        return share_snapshot_get(
            context, snapshot_values['id'], session=session)


@require_admin_context
def snapshot_data_get_for_project(context, project_id, user_id,
                                  share_type_id=None, session=None):
    query = (model_query(context, models.ShareSnapshot,
                         func.count(models.ShareSnapshot.id),
                         func.sum(models.ShareSnapshot.size),
                         read_deleted="no",
                         session=session).
             filter_by(project_id=project_id))

    if share_type_id:
        query = query.join(
            models.ShareInstance,
            models.ShareInstance.share_id == models.ShareSnapshot.share_id,
        ).filter_by(share_type_id=share_type_id)
    elif user_id:
        query = query.filter_by(user_id=user_id)
    result = query.first()

    return (result[0] or 0, result[1] or 0)


@require_context
def share_snapshot_get(context, snapshot_id, session=None):
    result = (model_query(context, models.ShareSnapshot, session=session,
                          project_only=True).
              filter_by(id=snapshot_id).
              options(joinedload('share')).
              options(joinedload('instances')).
              first())

    if not result:
        raise exception.ShareSnapshotNotFound(snapshot_id=snapshot_id)

    return result


def _share_snapshot_get_all_with_filters(context, project_id=None,
                                         share_id=None, filters=None,
                                         sort_key=None, sort_dir=None):
    # Init data
    sort_key = sort_key or 'share_id'
    sort_dir = sort_dir or 'desc'
    filters = filters or {}
    query = model_query(context, models.ShareSnapshot)

    if project_id:
        query = query.filter_by(project_id=project_id)
    if share_id:
        query = query.filter_by(share_id=share_id)
    query = query.options(joinedload('share'))
    query = query.options(joinedload('instances'))

    # Apply filters
    if 'usage' in filters:
        usage_filter_keys = ['any', 'used', 'unused']
        if filters['usage'] == 'any':
            pass
        elif filters['usage'] == 'used':
            query = query.filter(or_(models.Share.snapshot_id == (
                models.ShareSnapshot.id)))
        elif filters['usage'] == 'unused':
            query = query.filter(or_(models.Share.snapshot_id != (
                models.ShareSnapshot.id)))
        else:
            msg = _("Wrong 'usage' key provided - '%(key)s'. "
                    "Expected keys are '%(ek)s'.") % {
                        'key': filters['usage'],
                        'ek': six.text_type(usage_filter_keys)}
            raise exception.InvalidInput(reason=msg)

    # Apply sorting
    try:
        attr = getattr(models.ShareSnapshot, sort_key)
    except AttributeError:
        msg = _("Wrong sorting key provided - '%s'.") % sort_key
        raise exception.InvalidInput(reason=msg)
    if sort_dir.lower() == 'desc':
        query = query.order_by(attr.desc())
    elif sort_dir.lower() == 'asc':
        query = query.order_by(attr.asc())
    else:
        msg = _("Wrong sorting data provided: sort key is '%(sort_key)s' "
                "and sort direction is '%(sort_dir)s'.") % {
                    "sort_key": sort_key, "sort_dir": sort_dir}
        raise exception.InvalidInput(reason=msg)

    # Returns list of shares that satisfy filters
    return query.all()


@require_admin_context
def share_snapshot_get_all(context, filters=None, sort_key=None,
                           sort_dir=None):
    return _share_snapshot_get_all_with_filters(
        context, filters=filters, sort_key=sort_key, sort_dir=sort_dir,
    )


@require_context
def share_snapshot_get_all_by_project(context, project_id, filters=None,
                                      sort_key=None, sort_dir=None):
    authorize_project_context(context, project_id)
    return _share_snapshot_get_all_with_filters(
        context, project_id=project_id,
        filters=filters, sort_key=sort_key, sort_dir=sort_dir,
    )


@require_context
def share_snapshot_get_all_for_share(context, share_id, filters=None,
                                     sort_key=None, sort_dir=None):
    return _share_snapshot_get_all_with_filters(
        context, share_id=share_id,
        filters=filters, sort_key=sort_key, sort_dir=sort_dir,
    )


@require_context
def share_snapshot_get_latest_for_share(context, share_id):

    snapshots = _share_snapshot_get_all_with_filters(
        context, share_id=share_id, sort_key='created_at', sort_dir='desc')
    return snapshots[0] if snapshots else None


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def share_snapshot_update(context, snapshot_id, values):
    session = get_session()
    with session.begin():
        snapshot_ref = share_snapshot_get(context, snapshot_id,
                                          session=session)

        instance_values, snapshot_values = (
            _extract_snapshot_instance_values(values)
        )

        if snapshot_values:
            snapshot_ref.update(snapshot_values)
            snapshot_ref.save(session=session)

        if instance_values:
            snapshot_ref.instance.update(instance_values)
            snapshot_ref.instance.save(session=session)

        return snapshot_ref

#################################


@require_context
def share_snapshot_access_create(context, values):
    values = ensure_model_dict_has_id(values)
    session = get_session()
    with session.begin():
        access_ref = models.ShareSnapshotAccessMapping()
        access_ref.update(values)
        access_ref.save(session=session)

        snapshot = share_snapshot_get(context, values['share_snapshot_id'],
                                      session=session)

        for instance in snapshot.instances:
            vals = {
                'share_snapshot_instance_id': instance['id'],
                'access_id': access_ref['id'],
            }

            _share_snapshot_instance_access_create(vals, session)

    return share_snapshot_access_get(context, access_ref['id'])


def _share_snapshot_access_get_query(context, session, filters,
                                     read_deleted='no'):

    query = model_query(context, models.ShareSnapshotAccessMapping,
                        session=session, read_deleted=read_deleted)
    return query.filter_by(**filters)


def _share_snapshot_instance_access_get_query(context, session,
                                              access_id=None,
                                              share_snapshot_instance_id=None):
    filters = {'deleted': 'False'}

    if access_id is not None:
        filters.update({'access_id': access_id})

    if share_snapshot_instance_id is not None:
        filters.update(
            {'share_snapshot_instance_id': share_snapshot_instance_id})

    return model_query(context, models.ShareSnapshotInstanceAccessMapping,
                       session=session).filter_by(**filters)


@require_context
def share_snapshot_instance_access_get_all(context, access_id, session):
    rules = _share_snapshot_instance_access_get_query(
        context, session, access_id=access_id).all()
    return rules


@require_context
def share_snapshot_access_get(context, access_id, session=None):
    session = session or get_session()

    access = _share_snapshot_access_get_query(
        context, session, {'id': access_id}).first()

    if access:
        return access
    else:
        raise exception.NotFound()


def _share_snapshot_instance_access_create(values, session):
    access_ref = models.ShareSnapshotInstanceAccessMapping()
    access_ref.update(ensure_model_dict_has_id(values))
    access_ref.save(session=session)
    return access_ref


@require_context
def share_snapshot_access_get_all_for_share_snapshot(context,
                                                     share_snapshot_id,
                                                     filters):
    session = get_session()
    filters['share_snapshot_id'] = share_snapshot_id
    access_list = _share_snapshot_access_get_query(
        context, session, filters).all()

    return access_list


@require_context
def share_snapshot_check_for_existing_access(context, share_snapshot_id,
                                             access_type, access_to):
    return _check_for_existing_access(
        context, 'share_snapshot', share_snapshot_id, access_type, access_to)


@require_context
def share_snapshot_access_get_all_for_snapshot_instance(
        context, snapshot_instance_id, filters=None,
        with_snapshot_access_data=True, session=None):
    """Get all access rules related to a certain snapshot instance."""
    session = session or get_session()
    filters = copy.deepcopy(filters) if filters else {}
    filters.update({'share_snapshot_instance_id': snapshot_instance_id})

    query = _share_snapshot_instance_access_get_query(context, session)

    legal_filter_keys = (
        'id', 'share_snapshot_instance_id', 'access_id', 'state')

    query = exact_filter(
        query, models.ShareSnapshotInstanceAccessMapping, filters,
        legal_filter_keys)

    instance_accesses = query.all()

    if with_snapshot_access_data:
        instance_accesses = _set_instances_snapshot_access_data(
            context, instance_accesses, session)

    return instance_accesses


@require_context
def share_snapshot_instance_access_update(
        context, access_id, instance_id, updates):

    snapshot_access_fields = ('access_type', 'access_to')
    snapshot_access_map_updates, share_instance_access_map_updates = (
        _extract_subdict_by_fields(updates, snapshot_access_fields)
    )

    session = get_session()
    with session.begin():

        snapshot_access = _share_snapshot_access_get_query(
            context, session, {'id': access_id}).first()
        if not snapshot_access:
            raise exception.NotFound()
        snapshot_access.update(snapshot_access_map_updates)
        snapshot_access.save(session=session)

        access = _share_snapshot_instance_access_get_query(
            context, session, access_id=access_id,
            share_snapshot_instance_id=instance_id).first()
        if not access:
            raise exception.NotFound()
        access.update(share_instance_access_map_updates)
        access.save(session=session)

        return access


@require_context
def share_snapshot_instance_access_get(
        context, access_id, share_snapshot_instance_id,
        with_snapshot_access_data=True):

    session = get_session()

    with session.begin():
        access = _share_snapshot_instance_access_get_query(
            context, session, access_id=access_id,
            share_snapshot_instance_id=share_snapshot_instance_id).first()

        if access is None:
            raise exception.NotFound()

        if with_snapshot_access_data:
            return _set_instances_snapshot_access_data(
                context, access, session)[0]
        else:
            return access


@require_context
def share_snapshot_instance_access_delete(
        context, access_id, snapshot_instance_id):
    session = get_session()
    with session.begin():

        rule = _share_snapshot_instance_access_get_query(
            context, session, access_id=access_id,
            share_snapshot_instance_id=snapshot_instance_id).first()

        if not rule:
            exception.NotFound()

        rule.soft_delete(session, update_status=True,
                         status_field_name='state')

        other_mappings = share_snapshot_instance_access_get_all(
            context, rule['access_id'], session)

        if len(other_mappings) == 0:
            (
                session.query(models.ShareSnapshotAccessMapping)
                .filter_by(id=rule['access_id'])
                .soft_delete(update_status=True, status_field_name='state')
            )


@require_context
def share_snapshot_instance_export_location_create(context, values):

    values = ensure_model_dict_has_id(values)
    session = get_session()
    with session.begin():
        ssiel = models.ShareSnapshotInstanceExportLocation()
        ssiel.update(values)
        ssiel.save(session=session)

        return ssiel


def _share_snapshot_instance_export_locations_get_query(context, session,
                                                        values):
    query = model_query(context, models.ShareSnapshotInstanceExportLocation,
                        session=session)
    return query.filter_by(**values)


@require_context
def share_snapshot_export_locations_get(context, snapshot_id):
    session = get_session()
    snapshot = share_snapshot_get(context, snapshot_id, session=session)
    ins_ids = [ins['id'] for ins in snapshot.instances]
    export_locations = _share_snapshot_instance_export_locations_get_query(
        context, session, {}).filter(
        models.ShareSnapshotInstanceExportLocation.
            share_snapshot_instance_id.in_(ins_ids)).all()
    return export_locations


@require_context
def share_snapshot_instance_export_locations_get_all(
        context, share_snapshot_instance_id):

    session = get_session()
    export_locations = _share_snapshot_instance_export_locations_get_query(
        context, session,
        {'share_snapshot_instance_id': share_snapshot_instance_id}).all()
    return export_locations


@require_context
def share_snapshot_instance_export_location_get(context, el_id):
    session = get_session()

    export_location = _share_snapshot_instance_export_locations_get_query(
        context, session, {'id': el_id}).first()

    if export_location:
        return export_location
    else:
        raise exception.NotFound()


@require_context
def share_snapshot_instance_export_location_delete(context, el_id):
    session = get_session()
    with session.begin():

        el = _share_snapshot_instance_export_locations_get_query(
            context, session, {'id': el_id}).first()

        if not el:
            exception.NotFound()

        el.soft_delete(session=session)

#################################


@require_context
@require_share_exists
def share_metadata_get(context, share_id):
    return _share_metadata_get(context, share_id)


@require_context
@require_share_exists
def share_metadata_delete(context, share_id, key):
    (_share_metadata_get_query(context, share_id).
        filter_by(key=key).soft_delete())


@require_context
@require_share_exists
def share_metadata_update(context, share_id, metadata, delete):
    return _share_metadata_update(context, share_id, metadata, delete)


def _share_metadata_get_query(context, share_id, session=None):
    return (model_query(context, models.ShareMetadata, session=session,
                        read_deleted="no").
            filter_by(share_id=share_id).
            options(joinedload('share')))


def _share_metadata_get(context, share_id, session=None):
    rows = _share_metadata_get_query(context, share_id,
                                     session=session).all()
    result = {}
    for row in rows:
        result[row['key']] = row['value']

    return result


@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def _share_metadata_update(context, share_id, metadata, delete, session=None):
    if not session:
        session = get_session()

    with session.begin():
        # Set existing metadata to deleted if delete argument is True
        if delete:
            original_metadata = _share_metadata_get(context, share_id,
                                                    session=session)
            for meta_key, meta_value in original_metadata.items():
                if meta_key not in metadata:
                    meta_ref = _share_metadata_get_item(context, share_id,
                                                        meta_key,
                                                        session=session)
                    meta_ref.soft_delete(session=session)

        meta_ref = None

        # Now update all existing items with new values, or create new meta
        # objects
        for meta_key, meta_value in metadata.items():

            # update the value whether it exists or not
            item = {"value": meta_value}

            try:
                meta_ref = _share_metadata_get_item(context, share_id,
                                                    meta_key,
                                                    session=session)
            except exception.ShareMetadataNotFound:
                meta_ref = models.ShareMetadata()
                item.update({"key": meta_key, "share_id": share_id})

            meta_ref.update(item)
            meta_ref.save(session=session)

        return metadata


def _share_metadata_get_item(context, share_id, key, session=None):
    result = (_share_metadata_get_query(context, share_id, session=session).
              filter_by(key=key).
              first())

    if not result:
        raise exception.ShareMetadataNotFound(metadata_key=key,
                                              share_id=share_id)
    return result


############################
# Export locations functions
############################

def _share_export_locations_get(context, share_instance_ids,
                                include_admin_only=True, session=None):
    session = session or get_session()

    if not isinstance(share_instance_ids, (set, list, tuple)):
        share_instance_ids = (share_instance_ids, )

    query = model_query(
        context,
        models.ShareInstanceExportLocations,
        session=session,
        read_deleted="no",
    ).filter(
        models.ShareInstanceExportLocations.share_instance_id.in_(
            share_instance_ids),
    ).order_by(
        "updated_at",
    ).options(
        joinedload("_el_metadata_bare"),
    )

    if not include_admin_only:
        query = query.filter_by(is_admin_only=False)
    return query.all()


@require_context
@require_share_exists
def share_export_locations_get_by_share_id(context, share_id,
                                           include_admin_only=True,
                                           ignore_migration_destination=False):
    share = share_get(context, share_id)
    if ignore_migration_destination:
        ids = [instance.id for instance in share.instances
               if instance['status'] != constants.STATUS_MIGRATING_TO]
    else:
        ids = [instance.id for instance in share.instances]
    rows = _share_export_locations_get(
        context, ids, include_admin_only=include_admin_only)
    return rows


@require_context
@require_share_instance_exists
def share_export_locations_get_by_share_instance_id(context,
                                                    share_instance_id):
    rows = _share_export_locations_get(
        context, [share_instance_id], include_admin_only=True)
    return rows


@require_context
@require_share_exists
def share_export_locations_get(context, share_id):
    # NOTE(vponomaryov): this method is kept for compatibility with
    # old approach. New one uses 'share_export_locations_get_by_share_id'.
    # Which returns list of dicts instead of list of strings, as this one does.
    share = share_get(context, share_id)
    rows = _share_export_locations_get(
        context, share.instance.id, context.is_admin)

    return [location['path'] for location in rows]


@require_context
def share_export_location_get_by_uuid(context, export_location_uuid,
                                      session=None):
    session = session or get_session()

    query = model_query(
        context,
        models.ShareInstanceExportLocations,
        session=session,
        read_deleted="no",
    ).filter_by(
        uuid=export_location_uuid,
    ).options(
        joinedload("_el_metadata_bare"),
    )

    result = query.first()
    if not result:
        raise exception.ExportLocationNotFound(uuid=export_location_uuid)
    return result


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def share_export_locations_update(context, share_instance_id, export_locations,
                                  delete):
    # NOTE(u_glide):
    # Backward compatibility code for drivers,
    # which return single export_location as string
    if not isinstance(export_locations, (list, tuple, set)):
        export_locations = (export_locations, )
    export_locations_as_dicts = []
    for el in export_locations:
        # NOTE(vponomaryov): transform old export locations view to new one
        export_location = el
        if isinstance(el, six.string_types):
            export_location = {
                "path": el,
                "is_admin_only": False,
                "metadata": {},
            }
        elif isinstance(export_location, dict):
            if 'metadata' not in export_location:
                export_location['metadata'] = {}
        else:
            raise exception.ManilaException(
                _("Wrong export location type '%s'.") % type(export_location))
        export_locations_as_dicts.append(export_location)
    export_locations = export_locations_as_dicts

    export_locations_paths = [el['path'] for el in export_locations]

    session = get_session()

    current_el_rows = _share_export_locations_get(
        context, share_instance_id, session=session)

    def get_path_list_from_rows(rows):
        return set([l['path'] for l in rows])

    current_el_paths = get_path_list_from_rows(current_el_rows)

    def create_indexed_time_dict(key_list):
        base = timeutils.utcnow()
        return {
            # NOTE(u_glide): Incrementing timestamp by microseconds to make
            # timestamp order match index order.
            key: base + datetime.timedelta(microseconds=index)
            for index, key in enumerate(key_list)
        }

    indexed_update_time = create_indexed_time_dict(export_locations_paths)

    for el in current_el_rows:
        if delete and el['path'] not in export_locations_paths:
            export_location_metadata_delete(context, el['uuid'])
            el.soft_delete(session)
        else:
            updated_at = indexed_update_time[el['path']]
            el.update({
                'updated_at': updated_at,
                'deleted': 0,
            })
            el.save(session=session)
            if el['el_metadata']:
                export_location_metadata_update(
                    context, el['uuid'], el['el_metadata'], session=session)

    # Now add new export locations
    for el in export_locations:
        if el['path'] in current_el_paths:
            # Already updated
            continue

        location_ref = models.ShareInstanceExportLocations()
        location_ref.update({
            'uuid': uuidutils.generate_uuid(),
            'path': el['path'],
            'share_instance_id': share_instance_id,
            'updated_at': indexed_update_time[el['path']],
            'deleted': 0,
            'is_admin_only': el.get('is_admin_only', False),
        })
        location_ref.save(session=session)
        if not el.get('metadata'):
            continue
        export_location_metadata_update(
            context, location_ref['uuid'], el.get('metadata'), session=session)

    return get_path_list_from_rows(_share_export_locations_get(
        context, share_instance_id, session=session))


#####################################
# Export locations metadata functions
#####################################

def _export_location_metadata_get_query(context, export_location_uuid,
                                        session=None):
    session = session or get_session()
    export_location_id = share_export_location_get_by_uuid(
        context, export_location_uuid).id

    return model_query(
        context, models.ShareInstanceExportLocationsMetadata, session=session,
        read_deleted="no",
    ).filter_by(
        export_location_id=export_location_id,
    )


@require_context
def export_location_metadata_get(context, export_location_uuid, session=None):
    rows = _export_location_metadata_get_query(
        context, export_location_uuid, session=session).all()
    result = {}
    for row in rows:
        result[row["key"]] = row["value"]
    return result


@require_context
def export_location_metadata_delete(context, export_location_uuid, keys=None):
    session = get_session()
    metadata = _export_location_metadata_get_query(
        context, export_location_uuid, session=session,
    )
    # NOTE(vponomaryov): if keys is None then we delete all metadata.
    if keys is not None:
        keys = keys if isinstance(keys, (list, set, tuple)) else (keys, )
        metadata = metadata.filter(
            models.ShareInstanceExportLocationsMetadata.key.in_(keys))
    metadata = metadata.all()
    for meta_ref in metadata:
        meta_ref.soft_delete(session=session)


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def export_location_metadata_update(context, export_location_uuid, metadata,
                                    delete=False, session=None):
    session = session or get_session()
    if delete:
        original_metadata = export_location_metadata_get(
            context, export_location_uuid, session=session)
        keys_for_deletion = set(original_metadata).difference(metadata)
        if keys_for_deletion:
            export_location_metadata_delete(
                context, export_location_uuid, keys=keys_for_deletion)

    el = share_export_location_get_by_uuid(context, export_location_uuid)
    for meta_key, meta_value in metadata.items():
        # NOTE(vponomaryov): we should use separate session
        # for each meta_ref because of autoincrement of integer primary key
        # that will not take effect using one session and we will rewrite,
        # in that case, single record - first one added with this call.
        session = get_session()

        if meta_value is None:
            LOG.warning("%s should be properly defined in the driver.",
                        meta_key)

        item = {"value": meta_value, "updated_at": timeutils.utcnow()}

        meta_ref = _export_location_metadata_get_query(
            context, export_location_uuid, session=session,
        ).filter_by(
            key=meta_key,
        ).first()

        if not meta_ref:
            meta_ref = models.ShareInstanceExportLocationsMetadata()
            item.update({
                "key": meta_key,
                "export_location_id": el.id,
            })

        meta_ref.update(item)
        meta_ref.save(session=session)

    return metadata


###################################


@require_context
def security_service_create(context, values):
    values = ensure_model_dict_has_id(values)

    security_service_ref = models.SecurityService()
    security_service_ref.update(values)
    session = get_session()

    with session.begin():
        security_service_ref.save(session=session)

    return security_service_ref


@require_context
def security_service_delete(context, id):
    session = get_session()
    with session.begin():
        security_service_ref = security_service_get(context,
                                                    id,
                                                    session=session)
        security_service_ref.soft_delete(session)


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def security_service_update(context, id, values):
    session = get_session()
    with session.begin():
        security_service_ref = security_service_get(context,
                                                    id,
                                                    session=session)
        security_service_ref.update(values)
        security_service_ref.save(session=session)
        return security_service_ref


@require_context
def security_service_get(context, id, session=None):
    result = (_security_service_get_query(context, session=session).
              filter_by(id=id).first())

    if result is None:
        raise exception.SecurityServiceNotFound(security_service_id=id)
    return result


@require_context
def security_service_get_all(context):
    return _security_service_get_query(context).all()


@require_context
def security_service_get_all_by_project(context, project_id):
    return (_security_service_get_query(context).
            filter_by(project_id=project_id).all())


def _security_service_get_query(context, session=None):
    if session is None:
        session = get_session()
    return model_query(context, models.SecurityService, session=session)


###################


def _network_get_query(context, session=None):
    if session is None:
        session = get_session()
    return (model_query(context, models.ShareNetwork, session=session).
            options(joinedload('share_instances'),
                    joinedload('security_services'),
                    joinedload('share_servers')))


@require_context
def share_network_create(context, values):
    values = ensure_model_dict_has_id(values)

    network_ref = models.ShareNetwork()
    network_ref.update(values)
    session = get_session()
    with session.begin():
        network_ref.save(session=session)
    return share_network_get(context, values['id'], session)


@require_context
def share_network_delete(context, id):
    session = get_session()
    with session.begin():
        network_ref = share_network_get(context, id, session=session)
        network_ref.soft_delete(session)


@require_context
def share_network_update(context, id, values):
    session = get_session()
    with session.begin():
        network_ref = share_network_get(context, id, session=session)
        network_ref.update(values)
        network_ref.save(session=session)
        return network_ref


@require_context
def share_network_get(context, id, session=None):
    result = _network_get_query(context, session).filter_by(id=id).first()
    if result is None:
        raise exception.ShareNetworkNotFound(share_network_id=id)
    return result


@require_context
def share_network_get_all(context):
    return _network_get_query(context).all()


@require_context
def share_network_get_all_by_project(context, project_id):
    return _network_get_query(context).filter_by(project_id=project_id).all()


@require_context
def share_network_get_all_by_security_service(context, security_service_id):
    session = get_session()
    return (model_query(context, models.ShareNetwork, session=session).
            join(models.ShareNetworkSecurityServiceAssociation,
            models.ShareNetwork.id ==
            models.ShareNetworkSecurityServiceAssociation.share_network_id).
            filter_by(security_service_id=security_service_id, deleted=0).
            options(joinedload('share_servers')).all())


@require_context
def share_network_add_security_service(context, id, security_service_id):
    session = get_session()

    with session.begin():
        assoc_ref = (model_query(
                     context,
                     models.ShareNetworkSecurityServiceAssociation,
                     session=session).
                     filter_by(share_network_id=id).
                     filter_by(
                     security_service_id=security_service_id).first())

        if assoc_ref:
            msg = "Already associated"
            raise exception.ShareNetworkSecurityServiceAssociationError(
                share_network_id=id,
                security_service_id=security_service_id,
                reason=msg)

        share_nw_ref = share_network_get(context, id, session=session)
        security_service_ref = security_service_get(context,
                                                    security_service_id,
                                                    session=session)
        share_nw_ref.security_services += [security_service_ref]
        share_nw_ref.save(session=session)

    return share_nw_ref


@require_context
def share_network_remove_security_service(context, id, security_service_id):
    session = get_session()

    with session.begin():
        share_nw_ref = share_network_get(context, id, session=session)
        security_service_get(context, security_service_id, session=session)

        assoc_ref = (model_query(
            context,
            models.ShareNetworkSecurityServiceAssociation,
            session=session).
            filter_by(share_network_id=id).
            filter_by(security_service_id=security_service_id).first())

        if assoc_ref:
            assoc_ref.soft_delete(session)
        else:
            msg = "No association defined"
            raise exception.ShareNetworkSecurityServiceDissociationError(
                share_network_id=id,
                security_service_id=security_service_id,
                reason=msg)

    return share_nw_ref


@require_context
def count_share_networks(context, project_id, user_id=None,
                         share_type_id=None, session=None):
    query = model_query(
        context, models.ShareNetwork,
        func.count(models.ShareNetwork.id),
        read_deleted="no",
        session=session).filter_by(project_id=project_id)
    if share_type_id:
        query = query.join("share_instances").filter_by(
            share_type_id=share_type_id)
    elif user_id is not None:
        query = query.filter_by(user_id=user_id)
    return query.first()[0]


###################


def _server_get_query(context, session=None):
    if session is None:
        session = get_session()
    return (model_query(context, models.ShareServer, session=session).
            options(joinedload('share_instances'),
                    joinedload('network_allocations'),
                    joinedload('share_network')))


@require_context
def share_server_create(context, values):
    values = ensure_model_dict_has_id(values)

    server_ref = models.ShareServer()
    server_ref.update(values)
    session = get_session()
    with session.begin():
        server_ref.save(session=session)
        # NOTE(u_glide): Do so to prevent errors with relationships
        return share_server_get(context, server_ref['id'], session=session)


@require_context
def share_server_delete(context, id):
    session = get_session()
    with session.begin():
        server_ref = share_server_get(context, id, session=session)
        share_server_backend_details_delete(context, id, session=session)
        server_ref.soft_delete(session=session, update_status=True)


@require_context
def share_server_update(context, id, values):
    session = get_session()
    with session.begin():
        server_ref = share_server_get(context, id, session=session)
        server_ref.update(values)
        server_ref.save(session=session)
        return server_ref


@require_context
def share_server_get(context, server_id, session=None):
    result = (_server_get_query(context, session).filter_by(id=server_id)
              .first())
    if result is None:
        raise exception.ShareServerNotFound(share_server_id=server_id)
    return result


@require_context
def share_server_get_all_by_host_and_share_net_valid(context, host,
                                                     share_net_id,
                                                     session=None):
    result = (_server_get_query(context, session).filter_by(host=host)
              .filter_by(share_network_id=share_net_id)
              .filter(models.ShareServer.status.in_(
                      (constants.STATUS_CREATING,
                       constants.STATUS_ACTIVE))).all())
    if not result:
        filters_description = ('share_network_id is "%(share_net_id)s",'
                               ' host is "%(host)s" and status in'
                               ' "%(status_cr)s" or "%(status_act)s"') % {
            'share_net_id': share_net_id,
            'host': host,
            'status_cr': constants.STATUS_CREATING,
            'status_act': constants.STATUS_ACTIVE,
        }
        raise exception.ShareServerNotFoundByFilters(
            filters_description=filters_description)
    return result


@require_context
def share_server_get_all(context):
    return _server_get_query(context).all()


@require_context
def share_server_get_all_by_host(context, host):
    return _server_get_query(context).filter_by(host=host).all()


@require_context
def share_server_get_all_unused_deletable(context, host, updated_before):
    valid_server_status = (
        constants.STATUS_INACTIVE,
        constants.STATUS_ACTIVE,
        constants.STATUS_ERROR,
    )
    result = (_server_get_query(context)
              .filter_by(host=host)
              .filter(~models.ShareServer.share_groups.any())
              .filter(~models.ShareServer.share_instances.any())
              .filter(models.ShareServer.status.in_(valid_server_status))
              .filter(models.ShareServer.updated_at < updated_before).all())
    return result


@require_context
def share_server_backend_details_set(context, share_server_id, server_details):
    share_server_get(context, share_server_id)

    for meta_key, meta_value in server_details.items():
        meta_ref = models.ShareServerBackendDetails()
        meta_ref.update({
            'key': meta_key,
            'value': meta_value,
            'share_server_id': share_server_id
        })
        session = get_session()
        with session.begin():
            meta_ref.save(session)
    return server_details


@require_context
def share_server_backend_details_delete(context, share_server_id,
                                        session=None):
    if not session:
        session = get_session()
    share_server_details = (model_query(context,
                                        models.ShareServerBackendDetails,
                                        session=session)
                            .filter_by(share_server_id=share_server_id).all())
    for item in share_server_details:
        item.soft_delete(session)


###################

def _driver_private_data_query(session, context, entity_id, key=None,
                               read_deleted=False):
    query = model_query(
        context, models.DriverPrivateData, session=session,
        read_deleted=read_deleted,
    ).filter_by(
        entity_uuid=entity_id,
    )

    if isinstance(key, list):
        return query.filter(models.DriverPrivateData.key.in_(key))
    elif key is not None:
        return query.filter_by(key=key)

    return query


@require_context
def driver_private_data_get(context, entity_id, key=None,
                            default=None, session=None):
    if not session:
        session = get_session()

    query = _driver_private_data_query(session, context, entity_id, key)

    if key is None or isinstance(key, list):
        return {item.key: item.value for item in query.all()}
    else:
        result = query.first()
        return result["value"] if result is not None else default


@require_context
def driver_private_data_update(context, entity_id, details,
                               delete_existing=False, session=None):
    # NOTE(u_glide): following code modifies details dict, that's why we should
    # copy it
    new_details = copy.deepcopy(details)

    if not session:
        session = get_session()

    with session.begin():
        # Process existing data
        original_data = session.query(models.DriverPrivateData).filter_by(
            entity_uuid=entity_id).all()

        for data_ref in original_data:
            in_new_details = data_ref['key'] in new_details

            if in_new_details:
                new_value = six.text_type(new_details.pop(data_ref['key']))
                data_ref.update({
                    "value": new_value,
                    "deleted": 0,
                    "deleted_at": None
                })
                data_ref.save(session=session)
            elif delete_existing and data_ref['deleted'] != 1:
                data_ref.update({
                    "deleted": 1, "deleted_at": timeutils.utcnow()
                })
                data_ref.save(session=session)

        # Add new data
        for key, value in new_details.items():
            data_ref = models.DriverPrivateData()
            data_ref.update({
                "entity_uuid": entity_id,
                "key": key,
                "value": six.text_type(value)
            })
            data_ref.save(session=session)

        return details


@require_context
def driver_private_data_delete(context, entity_id, key=None,
                               session=None):
    if not session:
        session = get_session()

    with session.begin():
        query = _driver_private_data_query(session, context,
                                           entity_id, key)
        query.update({"deleted": 1, "deleted_at": timeutils.utcnow()})


###################


@require_context
def network_allocation_create(context, values):
    values = ensure_model_dict_has_id(values)
    alloc_ref = models.NetworkAllocation()
    alloc_ref.update(values)
    session = get_session()
    with session.begin():
        alloc_ref.save(session=session)
    return alloc_ref


@require_context
def network_allocation_delete(context, id):
    session = get_session()
    with session.begin():
        alloc_ref = network_allocation_get(context, id, session=session)
        alloc_ref.soft_delete(session)


@require_context
def network_allocation_get(context, id, session=None):
    if session is None:
        session = get_session()
    result = (model_query(context, models.NetworkAllocation, session=session).
              filter_by(id=id).first())
    if result is None:
        raise exception.NotFound()
    return result


@require_context
def network_allocations_get_by_ip_address(context, ip_address):
    session = get_session()
    result = (model_query(context, models.NetworkAllocation, session=session).
              filter_by(ip_address=ip_address).all())
    return result or []


@require_context
def network_allocations_get_for_share_server(context, share_server_id,
                                             session=None, label=None):
    if session is None:
        session = get_session()

    query = model_query(
        context, models.NetworkAllocation, session=session,
    ).filter_by(
        share_server_id=share_server_id,
    )
    if label:
        if label != 'admin':
            query = query.filter(or_(
                # NOTE(vponomaryov): we treat None as alias for 'user'.
                models.NetworkAllocation.label == None,  # noqa
                models.NetworkAllocation.label == label,
            ))
        else:
            query = query.filter(models.NetworkAllocation.label == label)

    result = query.all()
    return result


@require_context
def network_allocation_update(context, id, values):
    session = get_session()
    with session.begin():
        alloc_ref = network_allocation_get(context, id, session=session)
        alloc_ref.update(values)
        alloc_ref.save(session=session)
        return alloc_ref


###################


def _dict_with_specs(inst_type_query, specs_key='extra_specs'):
    """Convert type query result to dict with extra_spec and rate_limit.

    Takes a share [group] type query returned by sqlalchemy and returns it
    as a dictionary, converting the extra/group specs entry from a list
    of dicts:

    'extra_specs' : [{'key': 'k1', 'value': 'v1', ...}, ...]
    'group_specs' : [{'key': 'k1', 'value': 'v1', ...}, ...]
    to a single dict:
    'extra_specs' : {'k1': 'v1'}
    'group_specs' : {'k1': 'v1'}
    """
    inst_type_dict = dict(inst_type_query)
    specs = {x['key']: x['value'] for x in inst_type_query[specs_key]}
    inst_type_dict[specs_key] = specs
    return inst_type_dict


@require_admin_context
def share_type_create(context, values, projects=None):
    """Create a new share type.

    In order to pass in extra specs, the values dict should contain a
    'extra_specs' key/value pair:
    {'extra_specs' : {'k1': 'v1', 'k2': 'v2', ...}}
    """
    values = ensure_model_dict_has_id(values)

    projects = projects or []

    session = get_session()
    with session.begin():
        try:
            values['extra_specs'] = _metadata_refs(values.get('extra_specs'),
                                                   models.ShareTypeExtraSpecs)
            share_type_ref = models.ShareTypes()
            share_type_ref.update(values)
            share_type_ref.save(session=session)
        except db_exception.DBDuplicateEntry:
            raise exception.ShareTypeExists(id=values['name'])
        except Exception as e:
            raise db_exception.DBError(e)

        for project in set(projects):
            access_ref = models.ShareTypeProjects()
            access_ref.update({"share_type_id": share_type_ref.id,
                               "project_id": project})
            access_ref.save(session=session)

        return share_type_ref


def _share_type_get_query(context, session=None, read_deleted=None,
                          expected_fields=None):
    expected_fields = expected_fields or []
    query = (model_query(context,
                         models.ShareTypes,
                         session=session,
                         read_deleted=read_deleted).
             options(joinedload('extra_specs')))

    if 'projects' in expected_fields:
        query = query.options(joinedload('projects'))

    if not context.is_admin:
        the_filter = [models.ShareTypes.is_public == true()]
        projects_attr = getattr(models.ShareTypes, 'projects')
        the_filter.extend([
            projects_attr.any(project_id=context.project_id)
        ])
        query = query.filter(or_(*the_filter))

    return query


@require_context
def share_type_get_all(context, inactive=False, filters=None):
    """Returns a dict describing all share_types with name as key."""
    filters = filters or {}

    read_deleted = "yes" if inactive else "no"

    query = _share_type_get_query(context, read_deleted=read_deleted)

    if 'is_public' in filters and filters['is_public'] is not None:
        the_filter = [models. ShareTypes.is_public == filters['is_public']]
        if filters['is_public'] and context.project_id is not None:
            projects_attr = getattr(models. ShareTypes, 'projects')
            the_filter.extend([
                projects_attr.any(
                    project_id=context.project_id, deleted=0)
            ])
        if len(the_filter) > 1:
            query = query.filter(or_(*the_filter))
        else:
            query = query.filter(the_filter[0])

    rows = query.order_by("name").all()

    result = {}
    for row in rows:
        result[row['name']] = _dict_with_specs(row)

    return result


def _share_type_get_id_from_share_type_query(context, id, session=None):
    return (model_query(
            context, models.ShareTypes, read_deleted="no", session=session).
            filter_by(id=id))


def _share_type_get_id_from_share_type(context, id, session=None):
    result = _share_type_get_id_from_share_type_query(
        context, id, session=session).first()
    if not result:
        raise exception.ShareTypeNotFound(share_type_id=id)
    return result['id']


def _share_type_get(context, id, session=None, inactive=False,
                    expected_fields=None):
    expected_fields = expected_fields or []
    read_deleted = "yes" if inactive else "no"
    result = (_share_type_get_query(
              context, session, read_deleted, expected_fields).
              filter_by(id=id).
              first())

    if not result:
        # The only way that id could be None is if the default share type is
        # not configured and no other share type was specified.
        if id is None:
            raise exception.DefaultShareTypeNotConfigured()
        raise exception.ShareTypeNotFound(share_type_id=id)

    share_type = _dict_with_specs(result)

    if 'projects' in expected_fields:
        share_type['projects'] = [p['project_id'] for p in result['projects']]

    return share_type


@require_context
def share_type_get(context, id, inactive=False, expected_fields=None):
    """Return a dict describing specific share_type."""
    return _share_type_get(context, id,
                           session=None,
                           inactive=inactive,
                           expected_fields=expected_fields)


def _share_type_get_by_name(context, name, session=None):
    result = (model_query(context, models.ShareTypes, session=session).
              options(joinedload('extra_specs')).
              filter_by(name=name).
              first())

    if not result:
        raise exception.ShareTypeNotFoundByName(share_type_name=name)

    return _dict_with_specs(result)


@require_context
def share_type_get_by_name(context, name):
    """Return a dict describing specific share_type."""
    return _share_type_get_by_name(context, name)


@require_context
def share_type_get_by_name_or_id(context, name_or_id):
    """Return a dict describing specific share_type using its name or ID.

    :returns: ShareType object or None if not found
    """
    try:
        return _share_type_get(context, name_or_id)
    except exception.ShareTypeNotFound:
        try:
            return _share_type_get_by_name(context, name_or_id)
        except exception.ShareTypeNotFoundByName:
            return None


@require_admin_context
def share_type_destroy(context, id):
    session = get_session()
    with session.begin():
        _share_type_get(context, id, session)
        results = (model_query(context, models.ShareInstance, session=session,
                               read_deleted="no").
                   filter_by(share_type_id=id).count())
        share_group_count = model_query(
            context,
            models.ShareGroupShareTypeMapping,
            read_deleted="no",
            session=session,
        ).filter_by(share_type_id=id).count()
        if results or share_group_count:
            LOG.error('ShareType %s deletion failed, ShareType in use.',
                      id)
            raise exception.ShareTypeInUse(share_type_id=id)
        (model_query(context, models.ShareTypeExtraSpecs, session=session).
            filter_by(share_type_id=id).soft_delete())
        (model_query(context, models.ShareTypes, session=session).
            filter_by(id=id).soft_delete())

    # Destroy any quotas, usages and reservations for the share type:
    quota_destroy_all_by_share_type(context, id)


def _share_type_access_query(context, session=None):
    return model_query(context, models.ShareTypeProjects, session=session,
                       read_deleted="no")


@require_admin_context
def share_type_access_get_all(context, type_id):
    share_type_id = _share_type_get_id_from_share_type(context, type_id)
    return (_share_type_access_query(context).
            filter_by(share_type_id=share_type_id).all())


@require_admin_context
def share_type_access_add(context, type_id, project_id):
    """Add given tenant to the share type access list."""
    share_type_id = _share_type_get_id_from_share_type(context, type_id)

    access_ref = models.ShareTypeProjects()
    access_ref.update({"share_type_id": share_type_id,
                       "project_id": project_id})

    session = get_session()
    with session.begin():
        try:
            access_ref.save(session=session)
        except db_exception.DBDuplicateEntry:
            raise exception.ShareTypeAccessExists(share_type_id=type_id,
                                                  project_id=project_id)
        return access_ref


@require_admin_context
def share_type_access_remove(context, type_id, project_id):
    """Remove given tenant from the share type access list."""
    share_type_id = _share_type_get_id_from_share_type(context, type_id)

    count = (_share_type_access_query(context).
             filter_by(share_type_id=share_type_id).
             filter_by(project_id=project_id).
             soft_delete(synchronize_session=False))
    if count == 0:
        raise exception.ShareTypeAccessNotFound(
            share_type_id=type_id, project_id=project_id)

####################


def _share_type_extra_specs_query(context, share_type_id, session=None):
    return (model_query(context, models.ShareTypeExtraSpecs, session=session,
                        read_deleted="no").
            filter_by(share_type_id=share_type_id).
            options(joinedload('share_type')))


@require_context
def share_type_extra_specs_get(context, share_type_id):
    rows = (_share_type_extra_specs_query(context, share_type_id).
            all())

    result = {}
    for row in rows:
        result[row['key']] = row['value']

    return result


@require_context
def share_type_extra_specs_delete(context, share_type_id, key):
    session = get_session()
    with session.begin():
        _share_type_extra_specs_get_item(context, share_type_id, key, session)
        (_share_type_extra_specs_query(context, share_type_id, session).
            filter_by(key=key).soft_delete())


def _share_type_extra_specs_get_item(context, share_type_id, key,
                                     session=None):
    result = _share_type_extra_specs_query(
        context, share_type_id, session=session
    ).filter_by(key=key).options(joinedload('share_type')).first()

    if not result:
        raise exception.ShareTypeExtraSpecsNotFound(
            extra_specs_key=key,
            share_type_id=share_type_id)

    return result


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def share_type_extra_specs_update_or_create(context, share_type_id, specs):
    session = get_session()
    with session.begin():
        spec_ref = None
        for key, value in specs.items():
            try:
                spec_ref = _share_type_extra_specs_get_item(
                    context, share_type_id, key, session)
            except exception.ShareTypeExtraSpecsNotFound:
                spec_ref = models.ShareTypeExtraSpecs()
            spec_ref.update({"key": key, "value": value,
                             "share_type_id": share_type_id,
                             "deleted": 0})
            spec_ref.save(session=session)

        return specs


def _ensure_availability_zone_exists(context, values, session, strict=True):
    az_name = values.pop('availability_zone', None)

    if strict and not az_name:
        msg = _("Values dict should have 'availability_zone' field.")
        raise ValueError(msg)
    elif not az_name:
        return

    if uuidutils.is_uuid_like(az_name):
        az_ref = availability_zone_get(context, az_name, session=session)
    else:
        az_ref = availability_zone_create_if_not_exist(
            context, az_name, session=session)

    values.update({'availability_zone_id': az_ref['id']})


@require_context
def availability_zone_get(context, id_or_name, session=None):
    if session is None:
        session = get_session()

    query = model_query(context, models.AvailabilityZone, session=session)

    if uuidutils.is_uuid_like(id_or_name):
        query = query.filter_by(id=id_or_name)
    else:
        query = query.filter_by(name=id_or_name)

    result = query.first()

    if not result:
        raise exception.AvailabilityZoneNotFound(id=id_or_name)

    return result


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def availability_zone_create_if_not_exist(context, name, session=None):
    if session is None:
        session = get_session()

    az = models.AvailabilityZone()
    az.update({'id': uuidutils.generate_uuid(), 'name': name})
    try:
        with session.begin():
            az.save(session)
    # NOTE(u_glide): Do not catch specific exception here, because it depends
    # on concrete backend used by SqlAlchemy
    except Exception:
        return availability_zone_get(context, name, session=session)
    return az


@require_context
def availability_zone_get_all(context):
    session = get_session()

    enabled_services = model_query(
        context, models.Service,
        models.Service.availability_zone_id,
        session=session,
        read_deleted="no"
    ).filter_by(disabled=False).distinct()

    return model_query(context, models.AvailabilityZone, session=session,
                       read_deleted="no").filter(
        models.AvailabilityZone.id.in_(enabled_services)
    ).all()


@require_admin_context
def purge_deleted_records(context, age_in_days):
    """Purge soft-deleted records older than(and equal) age from tables."""

    if age_in_days < 0:
        msg = _('Must supply a non-negative value for "age_in_days".')
        LOG.error(msg)
        raise exception.InvalidParameterValue(msg)

    metadata = MetaData()
    metadata.reflect(get_engine())
    session = get_session()
    session.begin()
    deleted_age = timeutils.utcnow() - datetime.timedelta(days=age_in_days)

    for table in reversed(metadata.sorted_tables):
        if 'deleted' in table.columns.keys():
            try:
                mds = [m for m in models.__dict__.values() if
                       (hasattr(m, '__tablename__') and
                        m.__tablename__ == six.text_type(table))]
                if len(mds) > 0:
                    # collect all soft-deleted records
                    with session.begin_nested():
                        model = mds[0]
                        s_deleted_records = session.query(model).filter(
                            model.deleted_at <= deleted_age)
                    deleted_count = 0
                    # delete records one by one,
                    # skip the records which has FK constraints
                    for record in s_deleted_records:
                        try:
                            with session.begin_nested():
                                session.delete(record)
                                deleted_count += 1
                        except db_exc.DBError:
                            LOG.warning(
                                ("Deleting soft-deleted resource %s "
                                 "failed, skipping."), record)
                    if deleted_count != 0:
                        LOG.info("Deleted %(count)s records in "
                                 "table %(table)s.",
                                 {'count': deleted_count, 'table': table})
            except db_exc.DBError:
                LOG.warning("Querying table %s's soft-deleted records "
                            "failed, skipping.", table)
    session.commit()


####################


def _share_group_get(context, share_group_id, session=None):
    session = session or get_session()
    result = (model_query(context, models.ShareGroup,
                          session=session,
                          project_only=True,
                          read_deleted='no').
              filter_by(id=share_group_id).
              options(joinedload('share_types')).
              first())

    if not result:
        raise exception.ShareGroupNotFound(share_group_id=share_group_id)

    return result


@require_context
def share_group_get(context, share_group_id, session=None):
    return _share_group_get(context, share_group_id, session=session)


def _share_group_get_all(context, project_id=None, share_server_id=None,
                         host=None, detailed=True, filters=None,
                         sort_key=None, sort_dir=None, session=None):
    session = session or get_session()
    sort_key = sort_key or 'created_at'
    sort_dir = sort_dir or 'desc'

    query = model_query(
        context, models.ShareGroup, session=session, read_deleted='no')

    # Apply filters
    if not filters:
        filters = {}
    no_key = 'key_is_absent'
    for k, v in filters.items():
        temp_k = k.rstrip('~') if k in constants.LIKE_FILTER else k
        filter_attr = getattr(models.ShareGroup, temp_k, no_key)

        if filter_attr == no_key:
            msg = _("Share groups cannot be filtered using '%s' key.")
            raise exception.InvalidInput(reason=msg % k)

        if k in constants.LIKE_FILTER:
            query = query.filter(filter_attr.op('LIKE')(u'%' + v + u'%'))
        else:
            query = query.filter(filter_attr == v)

    if project_id:
        query = query.filter(
            models.ShareGroup.project_id == project_id)
    if host:
        query = query.filter(
            models.ShareGroup.host == host)
    if share_server_id:
        query = query.filter(
            models.ShareGroup.share_server_id == share_server_id)

    try:
        query = apply_sorting(models.ShareGroup, query, sort_key, sort_dir)
    except AttributeError:
        msg = _("Wrong sorting key provided - '%s'.") % sort_key
        raise exception.InvalidInput(reason=msg)

    if detailed:
        return query.options(joinedload('share_types')).all()
    else:
        query = query.with_entities(
            models.ShareGroup.id, models.ShareGroup.name)
        values = []
        for sg_id, sg_name in query.all():
            values.append({"id": sg_id, "name": sg_name})
        return values


@require_admin_context
def share_group_get_all(context, detailed=True, filters=None, sort_key=None,
                        sort_dir=None):
    return _share_group_get_all(
        context, detailed=detailed, filters=filters,
        sort_key=sort_key, sort_dir=sort_dir)


@require_admin_context
def share_group_get_all_by_host(context, host, detailed=True):
    return _share_group_get_all(context, host=host, detailed=detailed)


@require_context
def share_group_get_all_by_project(context, project_id, detailed=True,
                                   filters=None, sort_key=None, sort_dir=None):
    authorize_project_context(context, project_id)
    return _share_group_get_all(
        context, project_id=project_id, detailed=detailed, filters=filters,
        sort_key=sort_key, sort_dir=sort_dir)


@require_context
def share_group_get_all_by_share_server(context, share_server_id, filters=None,
                                        sort_key=None, sort_dir=None):
    return _share_group_get_all(
        context, share_server_id=share_server_id, filters=filters,
        sort_key=sort_key, sort_dir=sort_dir)


@require_context
def share_group_create(context, values):
    share_group = models.ShareGroup()
    if not values.get('id'):
        values['id'] = six.text_type(uuidutils.generate_uuid())

    mappings = []
    for item in values.get('share_types') or []:
        mapping = models.ShareGroupShareTypeMapping()
        mapping['id'] = six.text_type(uuidutils.generate_uuid())
        mapping['share_type_id'] = item
        mapping['share_group_id'] = values['id']
        mappings.append(mapping)

    values['share_types'] = mappings

    session = get_session()
    with session.begin():
        share_group.update(values)
        session.add(share_group)

        return _share_group_get(context, values['id'], session=session)


@require_context
def share_group_update(context, share_group_id, values):
    session = get_session()
    with session.begin():
        share_group_ref = _share_group_get(
            context, share_group_id, session=session)
        share_group_ref.update(values)
        share_group_ref.save(session=session)
        return share_group_ref


@require_admin_context
def share_group_destroy(context, share_group_id):
    session = get_session()
    with session.begin():
        share_group_ref = _share_group_get(
            context, share_group_id, session=session)
        share_group_ref.soft_delete(session)
        session.query(models.ShareGroupShareTypeMapping).filter_by(
            share_group_id=share_group_ref['id']).soft_delete()


@require_context
def count_shares_in_share_group(context, share_group_id, session=None):
    session = session or get_session()
    return (model_query(context, models.Share, session=session,
                        project_only=True, read_deleted="no").
            filter_by(share_group_id=share_group_id).
            count())


@require_context
def get_all_shares_by_share_group(context, share_group_id, session=None):
    session = session or get_session()
    return (model_query(
            context, models.Share, session=session,
            project_only=True, read_deleted="no").
            filter_by(share_group_id=share_group_id).
            all())


@require_context
def count_share_groups(context, project_id, user_id=None,
                       share_type_id=None, session=None):
    query = model_query(
        context, models.ShareGroup,
        func.count(models.ShareGroup.id),
        read_deleted="no",
        session=session).filter_by(project_id=project_id)
    if share_type_id:
        query = query.join("share_group_share_type_mappings").filter_by(
            share_type_id=share_type_id)
    elif user_id is not None:
        query = query.filter_by(user_id=user_id)
    return query.first()[0]


@require_context
def count_share_group_snapshots(context, project_id, user_id=None,
                                share_type_id=None, session=None):
    query = model_query(
        context, models.ShareGroupSnapshot,
        func.count(models.ShareGroupSnapshot.id),
        read_deleted="no",
        session=session).filter_by(project_id=project_id)
    if share_type_id:
        query = query.join(
            "share_group"
        ).join(
            "share_group_share_type_mappings"
        ).filter_by(share_type_id=share_type_id)
    elif user_id is not None:
        query = query.filter_by(user_id=user_id)
    return query.first()[0]


@require_context
def count_share_group_snapshots_in_share_group(context, share_group_id,
                                               session=None):
    session = session or get_session()
    return model_query(
        context, models.ShareGroupSnapshot, session=session,
        project_only=True, read_deleted="no",
    ).filter_by(
        share_group_id=share_group_id,
    ).count()


@require_context
def count_share_groups_in_share_network(context, share_network_id,
                                        session=None):
    session = session or get_session()
    return (model_query(
            context, models.ShareGroup, session=session,
            project_only=True, read_deleted="no").
            filter_by(share_network_id=share_network_id).
            count())


@require_context
def count_share_group_snapshot_members_in_share(context, share_id,
                                                session=None):
    session = session or get_session()
    return model_query(
        context, models.ShareSnapshotInstance, session=session,
        project_only=True, read_deleted="no",
    ).join(
        models.ShareInstance,
        models.ShareInstance.id == (
            models.ShareSnapshotInstance.share_instance_id),
    ).filter(
        models.ShareInstance.share_id == share_id,
    ).count()


@require_context
def _share_group_snapshot_get(context, share_group_snapshot_id, session=None):
    session = session or get_session()
    result = model_query(
        context, models.ShareGroupSnapshot, session=session,
        project_only=True, read_deleted='no',
    ).options(
        joinedload('share_group'),
        joinedload('share_group_snapshot_members'),
    ).filter_by(
        id=share_group_snapshot_id,
    ).first()

    if not result:
        raise exception.ShareGroupSnapshotNotFound(
            share_group_snapshot_id=share_group_snapshot_id)

    return result


def _share_group_snapshot_get_all(
        context, project_id=None, detailed=True, filters=None,
        sort_key=None, sort_dir=None, session=None):
    session = session or get_session()
    if not sort_key:
        sort_key = 'created_at'
    if not sort_dir:
        sort_dir = 'desc'

    query = model_query(
        context, models.ShareGroupSnapshot, session=session, read_deleted='no',
    ).options(
        joinedload('share_group'),
        joinedload('share_group_snapshot_members'),
    )

    # Apply filters
    if not filters:
        filters = {}
    no_key = 'key_is_absent'
    for k, v in filters.items():
        filter_attr = getattr(models.ShareGroupSnapshot, k, no_key)
        if filter_attr == no_key:
            msg = _("Share group snapshots cannot be filtered using '%s' key.")
            raise exception.InvalidInput(reason=msg % k)
        query = query.filter(filter_attr == v)

    if project_id:
        query = query.filter(
            models.ShareGroupSnapshot.project_id == project_id)

    try:
        query = apply_sorting(
            models.ShareGroupSnapshot, query, sort_key, sort_dir)
    except AttributeError:
        msg = _("Wrong sorting key provided - '%s'.") % sort_key
        raise exception.InvalidInput(reason=msg)

    if detailed:
        return query.all()
    else:
        query = query.with_entities(models.ShareGroupSnapshot.id,
                                    models.ShareGroupSnapshot.name)
        values = []
        for sgs_id, sgs_name in query.all():
            values.append({"id": sgs_id, "name": sgs_name})
        return values


@require_context
def share_group_snapshot_get(context, share_group_snapshot_id, session=None):
    session = session or get_session()
    return _share_group_snapshot_get(
        context, share_group_snapshot_id, session=session)


@require_admin_context
def share_group_snapshot_get_all(
        context, detailed=True, filters=None, sort_key=None, sort_dir=None):
    return _share_group_snapshot_get_all(
        context, filters=filters, detailed=detailed,
        sort_key=sort_key, sort_dir=sort_dir)


@require_context
def share_group_snapshot_get_all_by_project(
        context, project_id, detailed=True, filters=None,
        sort_key=None, sort_dir=None):
    authorize_project_context(context, project_id)
    return _share_group_snapshot_get_all(
        context, project_id=project_id, filters=filters, detailed=detailed,
        sort_key=sort_key, sort_dir=sort_dir,
    )


@require_context
def share_group_snapshot_create(context, values):
    share_group_snapshot = models.ShareGroupSnapshot()
    if not values.get('id'):
        values['id'] = six.text_type(uuidutils.generate_uuid())

    session = get_session()
    with session.begin():
        share_group_snapshot.update(values)
        session.add(share_group_snapshot)

        return _share_group_snapshot_get(
            context, values['id'], session=session)


@require_context
def share_group_snapshot_update(context, share_group_snapshot_id, values):
    session = get_session()
    with session.begin():
        share_group_ref = _share_group_snapshot_get(
            context, share_group_snapshot_id, session=session)
        share_group_ref.update(values)
        share_group_ref.save(session=session)
        return share_group_ref


@require_admin_context
def share_group_snapshot_destroy(context, share_group_snapshot_id):
    session = get_session()
    with session.begin():
        share_group_snap_ref = _share_group_snapshot_get(
            context, share_group_snapshot_id, session=session)
        share_group_snap_ref.soft_delete(session)
        session.query(models.ShareSnapshotInstance).filter_by(
            share_group_snapshot_id=share_group_snapshot_id).soft_delete()


@require_context
def share_group_snapshot_members_get_all(context, share_group_snapshot_id,
                                         session=None):
    session = session or get_session()
    query = model_query(
        context, models.ShareSnapshotInstance, session=session,
        read_deleted='no',
    ).filter_by(share_group_snapshot_id=share_group_snapshot_id)
    return query.all()


@require_context
def share_group_snapshot_member_get(context, member_id, session=None):
    result = model_query(
        context, models.ShareSnapshotInstance, session=session,
        project_only=True, read_deleted='no',
    ).filter_by(id=member_id).first()
    if not result:
        raise exception.ShareGroupSnapshotMemberNotFound(member_id=member_id)
    return result


@require_context
def share_group_snapshot_member_create(context, values):
    member = models.ShareSnapshotInstance()
    if not values.get('id'):
        values['id'] = six.text_type(uuidutils.generate_uuid())

    session = get_session()
    with session.begin():
        member.update(values)
        session.add(member)

        return share_group_snapshot_member_get(
            context, values['id'], session=session)


@require_context
def share_group_snapshot_member_update(context, member_id, values):
    session = get_session()
    with session.begin():
        member = share_group_snapshot_member_get(
            context, member_id, session=session)
        member.update(values)
        session.add(member)
        return share_group_snapshot_member_get(
            context, member_id, session=session)


####################


@require_admin_context
def share_group_type_create(context, values, projects=None):
    """Create a new share group type.

    In order to pass in group specs, the values dict should contain a
    'group_specs' key/value pair:
    {'group_specs' : {'k1': 'v1', 'k2': 'v2', ...}}
    """
    values = ensure_model_dict_has_id(values)

    projects = projects or []

    session = get_session()
    with session.begin():
        try:
            values['group_specs'] = _metadata_refs(
                values.get('group_specs'), models.ShareGroupTypeSpecs)
            mappings = []
            for item in values.get('share_types', []):
                share_type = share_type_get_by_name_or_id(context, item)
                if not share_type:
                    raise exception.ShareTypeDoesNotExist(share_type=item)
                mapping = models.ShareGroupTypeShareTypeMapping()
                mapping['id'] = six.text_type(uuidutils.generate_uuid())
                mapping['share_type_id'] = share_type['id']
                mapping['share_group_type_id'] = values['id']
                mappings.append(mapping)

            values['share_types'] = mappings
            share_group_type_ref = models.ShareGroupTypes()
            share_group_type_ref.update(values)
            share_group_type_ref.save(session=session)
        except db_exception.DBDuplicateEntry:
            raise exception.ShareGroupTypeExists(type_id=values['name'])
        except exception.ShareTypeDoesNotExist:
            raise
        except Exception as e:
            raise db_exception.DBError(e)

        for project in set(projects):
            access_ref = models.ShareGroupTypeProjects()
            access_ref.update({"share_group_type_id": share_group_type_ref.id,
                               "project_id": project})
            access_ref.save(session=session)

        return share_group_type_ref


def _share_group_type_get_query(context, session=None, read_deleted=None,
                                expected_fields=None):
    expected_fields = expected_fields or []
    query = model_query(
        context, models.ShareGroupTypes, session=session,
        read_deleted=read_deleted
    ).options(
        joinedload('group_specs'),
        joinedload('share_types'),
    )

    if 'projects' in expected_fields:
        query = query.options(joinedload('projects'))

    if not context.is_admin:
        the_filter = [models.ShareGroupTypes.is_public == true()]
        projects_attr = getattr(models.ShareGroupTypes, 'projects')
        the_filter.extend([
            projects_attr.any(project_id=context.project_id)
        ])
        query = query.filter(or_(*the_filter))

    return query


@require_context
def share_group_type_get_all(context, inactive=False, filters=None):
    """Returns a dict describing all share group types with name as key."""
    filters = filters or {}
    read_deleted = "yes" if inactive else "no"
    query = _share_group_type_get_query(context, read_deleted=read_deleted)

    if 'is_public' in filters and filters['is_public'] is not None:
        the_filter = [models.ShareGroupTypes.is_public == filters['is_public']]
        if filters['is_public'] and context.project_id is not None:
            projects_attr = getattr(models. ShareGroupTypes, 'projects')
            the_filter.extend([
                projects_attr.any(
                    project_id=context.project_id, deleted=0)
            ])
        if len(the_filter) > 1:
            query = query.filter(or_(*the_filter))
        else:
            query = query.filter(the_filter[0])

    rows = query.order_by("name").all()

    result = {}
    for row in rows:
        result[row['name']] = _dict_with_specs(row, 'group_specs')

    return result


def _share_group_type_get_id_from_share_group_type_query(context, type_id,
                                                         session=None):
    return model_query(
        context, models.ShareGroupTypes, read_deleted="no", session=session,
    ).filter_by(id=type_id)


def _share_group_type_get_id_from_share_group_type(context, type_id,
                                                   session=None):
    result = _share_group_type_get_id_from_share_group_type_query(
        context, type_id, session=session).first()
    if not result:
        raise exception.ShareGroupTypeNotFound(type_id=type_id)
    return result['id']


@require_context
def _share_group_type_get(context, type_id, session=None, inactive=False,
                          expected_fields=None):
    expected_fields = expected_fields or []
    read_deleted = "yes" if inactive else "no"
    result = _share_group_type_get_query(
        context, session, read_deleted, expected_fields,
    ).filter_by(id=type_id).first()

    if not result:
        raise exception.ShareGroupTypeNotFound(type_id=type_id)

    share_group_type = _dict_with_specs(result, 'group_specs')

    if 'projects' in expected_fields:
        share_group_type['projects'] = [
            p['project_id'] for p in result['projects']]

    return share_group_type


@require_context
def share_group_type_get(context, type_id, inactive=False,
                         expected_fields=None):
    """Return a dict describing specific share group type."""
    return _share_group_type_get(
        context, type_id, session=None, inactive=inactive,
        expected_fields=expected_fields)


@require_context
def _share_group_type_get_by_name(context, name, session=None):
    result = model_query(
        context, models.ShareGroupTypes, session=session,
    ).options(
        joinedload('group_specs'),
        joinedload('share_types'),
    ).filter_by(
        name=name,
    ).first()
    if not result:
        raise exception.ShareGroupTypeNotFoundByName(type_name=name)
    return _dict_with_specs(result, 'group_specs')


@require_context
def share_group_type_get_by_name(context, name):
    """Return a dict describing specific share group type."""
    return _share_group_type_get_by_name(context, name)


@require_admin_context
def share_group_type_destroy(context, type_id):
    session = get_session()
    with session.begin():
        _share_group_type_get(context, type_id, session)
        results = model_query(
            context, models.ShareGroup, session=session, read_deleted="no",
        ).filter_by(
            share_group_type_id=type_id,
        ).count()
        if results:
            LOG.error('Share group type %s deletion failed, it in use.',
                      type_id)
            raise exception.ShareGroupTypeInUse(type_id=type_id)
        model_query(
            context, models.ShareGroupTypeSpecs, session=session,
        ).filter_by(
            share_group_type_id=type_id,
        ).soft_delete()
        model_query(
            context, models.ShareGroupTypes, session=session
        ).filter_by(
            id=type_id,
        ).soft_delete()


def _share_group_type_access_query(context, session=None):
    return model_query(context, models.ShareGroupTypeProjects, session=session,
                       read_deleted="no")


@require_admin_context
def share_group_type_access_get_all(context, type_id):
    share_group_type_id = _share_group_type_get_id_from_share_group_type(
        context, type_id)
    return _share_group_type_access_query(context).filter_by(
        share_group_type_id=share_group_type_id,
    ).all()


@require_admin_context
def share_group_type_access_add(context, type_id, project_id):
    """Add given tenant to the share group type  access list."""
    share_group_type_id = _share_group_type_get_id_from_share_group_type(
        context, type_id)
    access_ref = models.ShareGroupTypeProjects()
    access_ref.update({"share_group_type_id": share_group_type_id,
                       "project_id": project_id})
    session = get_session()
    with session.begin():
        try:
            access_ref.save(session=session)
        except db_exception.DBDuplicateEntry:
            raise exception.ShareGroupTypeAccessExists(
                type_id=share_group_type_id, project_id=project_id)
        return access_ref


@require_admin_context
def share_group_type_access_remove(context, type_id, project_id):
    """Remove given tenant from the share group type access list."""
    share_group_type_id = _share_group_type_get_id_from_share_group_type(
        context, type_id)
    count = _share_group_type_access_query(context).filter_by(
        share_group_type_id=share_group_type_id,
    ).filter_by(
        project_id=project_id,
    ).soft_delete(
        synchronize_session=False,
    )
    if count == 0:
        raise exception.ShareGroupTypeAccessNotFound(
            type_id=share_group_type_id, project_id=project_id)


def _share_group_type_specs_query(context, type_id, session=None):
    return model_query(
        context, models.ShareGroupTypeSpecs, session=session, read_deleted="no"
    ).filter_by(
        share_group_type_id=type_id,
    ).options(
        joinedload('share_group_type'),
    )


@require_context
def share_group_type_specs_get(context, type_id):
    rows = _share_group_type_specs_query(context, type_id).all()
    result = {}
    for row in rows:
        result[row['key']] = row['value']
    return result


@require_context
def share_group_type_specs_delete(context, type_id, key):
    session = get_session()
    with session.begin():
        _share_group_type_specs_get_item(context, type_id, key, session)
        _share_group_type_specs_query(
            context, type_id, session,
        ).filter_by(
            key=key,
        ).soft_delete()


@require_context
def _share_group_type_specs_get_item(context, type_id, key, session=None):
    result = _share_group_type_specs_query(
        context, type_id, session=session,
    ).filter_by(
        key=key,
    ).options(
        joinedload('share_group_type'),
    ).first()

    if not result:
        raise exception.ShareGroupTypeSpecsNotFound(
            specs_key=key, type_id=type_id)

    return result


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def share_group_type_specs_update_or_create(context, type_id, specs):
    session = get_session()
    with session.begin():
        spec_ref = None
        for key, value in specs.items():
            try:
                spec_ref = _share_group_type_specs_get_item(
                    context, type_id, key, session)
            except exception.ShareGroupTypeSpecsNotFound:
                spec_ref = models.ShareGroupTypeSpecs()
            spec_ref.update({"key": key, "value": value,
                             "share_group_type_id": type_id, "deleted": 0})
            spec_ref.save(session=session)

        return specs


###############################


@require_context
def message_get(context, message_id):
    query = model_query(context,
                        models.Message,
                        read_deleted="no",
                        project_only="yes")
    result = query.filter_by(id=message_id).first()
    if not result:
        raise exception.MessageNotFound(message_id=message_id)
    return result


@require_context
def message_get_all(context, filters=None, sort_key='created_at',
                    sort_dir='asc'):
    messages = models.Message
    query = model_query(context,
                        messages,
                        read_deleted="no",
                        project_only="yes")

    legal_filter_keys = ('request_id', 'resource_type', 'resource_id',
                         'action_id', 'detail_id', 'message_level')

    if not filters:
        filters = {}

    query = exact_filter(query, messages, filters, legal_filter_keys)
    try:
        query = apply_sorting(messages, query, sort_key, sort_dir)
    except AttributeError:
        msg = _("Wrong sorting key provided - '%s'.") % sort_key
        raise exception.InvalidInput(reason=msg)

    return query.all()


@require_context
def message_create(context, message_values):
    values = copy.deepcopy(message_values)
    message_ref = models.Message()
    if not values.get('id'):
        values['id'] = uuidutils.generate_uuid()
    message_ref.update(values)

    session = get_session()
    with session.begin():
        session.add(message_ref)

    return message_get(context, message_ref['id'])


@require_context
def message_destroy(context, message):
    session = get_session()
    with session.begin():
        (model_query(context, models.Message, session=session).
            filter_by(id=message.get('id')).soft_delete())


@require_admin_context
def cleanup_expired_messages(context):
    session = get_session()
    now = timeutils.utcnow()
    with session.begin():
        return session.query(models.Message).filter(
            models.Message.expires_at < now).delete()


@require_context
def backend_info_get(context, host):
    """Get hash info for given host."""
    session = get_session()

    result = _backend_info_query(session, context, host)

    return result


@require_context
def backend_info_create(context, host, value):
    session = get_session()
    with session.begin():
        info_ref = models.BackendInfo()
        info_ref.update({"host": host,
                         "info_hash": value})
        info_ref.save(session)
        return info_ref


@require_context
def backend_info_update(context, host, value=None, delete_existing=False):
    """Remove backend info for host name."""
    session = get_session()

    with session.begin():
        info_ref = _backend_info_query(session, context, host)
        if info_ref:
            if value:
                info_ref.update({"info_hash": value})
            elif delete_existing and info_ref['deleted'] != 1:
                info_ref.update({"deleted": 1,
                                 "deleted_at": timeutils.utcnow()})
        else:
            info_ref = models.BackendInfo()
            info_ref.update({"host": host,
                             "info_hash": value})
        info_ref.save(session)
        return info_ref


def _backend_info_query(session, context, host, read_deleted=False):
    result = model_query(
        context, models.BackendInfo, session=session,
        read_deleted=read_deleted,
    ).filter_by(
        host=host,
    ).first()

    return result
