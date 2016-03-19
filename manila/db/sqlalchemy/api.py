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
import sys
import uuid
import warnings

# NOTE(uglide): Required to override default oslo_db Query class
import manila.db.sqlalchemy.query  # noqa

from oslo_config import cfg
from oslo_db import api as oslo_db_api
from oslo_db import exception as db_exception
from oslo_db import options as db_options
from oslo_db.sqlalchemy import session
from oslo_db.sqlalchemy import utils as db_utils
from oslo_log import log
from oslo_utils import timeutils
from oslo_utils import uuidutils
import six
from sqlalchemy import or_
from sqlalchemy.orm import joinedload
from sqlalchemy.sql.expression import true
from sqlalchemy.sql import func

from manila.common import constants
from manila.db.sqlalchemy import models
from manila import exception
from manila.i18n import _
from manila.i18n import _LE
from manila.i18n import _LW

CONF = cfg.CONF

LOG = log.getLogger(__name__)

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

    def wrapper(context, share_instance_id, *args, **kwargs):
        share_instance_get(context, share_instance_id)
        return f(context, share_instance_id, *args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper


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


def _sync_shares(context, project_id, user_id, session):
    (shares, gigs) = share_data_get_for_project(context,
                                                project_id,
                                                user_id,
                                                session=session)
    return {'shares': shares}


def _sync_snapshots(context, project_id, user_id, session):
    (snapshots, gigs) = snapshot_data_get_for_project(context,
                                                      project_id,
                                                      user_id,
                                                      session=session)
    return {'snapshots': snapshots}


def _sync_gigabytes(context, project_id, user_id, session):
    _junk, share_gigs = share_data_get_for_project(
        context, project_id, user_id, session=session)
    return dict(gigabytes=share_gigs)


def _sync_snapshot_gigabytes(context, project_id, user_id, session):
    _junk, snapshot_gigs = snapshot_data_get_for_project(
        context, project_id, user_id, session=session)
    return dict(snapshot_gigabytes=snapshot_gigs)


def _sync_share_networks(context, project_id, user_id, session):
    share_networks = share_network_get_all_by_project(context,
                                                      project_id,
                                                      user_id,
                                                      session=session)
    return {'share_networks': len(share_networks)}


QUOTA_SYNC_FUNCTIONS = {
    '_sync_shares': _sync_shares,
    '_sync_snapshots': _sync_snapshots,
    '_sync_gigabytes': _sync_gigabytes,
    '_sync_snapshot_gigabytes': _sync_snapshot_gigabytes,
    '_sync_share_networks': _sync_share_networks,
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
    result = model_query(
        context,
        models.Service,
        session=session).\
        filter_by(id=service_id).\
        first()
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
    return model_query(
        context, models.Service, read_deleted="no").\
        filter_by(disabled=False).\
        filter_by(topic=topic).\
        all()


@require_admin_context
def service_get_by_host_and_topic(context, host, topic):
    result = model_query(
        context, models.Service, read_deleted="no").\
        filter_by(disabled=False).\
        filter_by(host=host).\
        filter_by(topic=topic).\
        first()
    if not result:
        raise exception.ServiceNotFound(service_id=host)
    return result


@require_admin_context
def service_get_all_by_host(context, host):
    return model_query(
        context, models.Service, read_deleted="no").\
        filter_by(host=host).\
        all()


@require_admin_context
def _service_get_all_topic_subquery(context, session, topic, subq, label):
    sort_value = getattr(subq.c, label)
    return model_query(context, models.Service,
                       func.coalesce(sort_value, 0),
                       session=session, read_deleted="no").\
        filter_by(topic=topic).\
        filter_by(disabled=False).\
        outerjoin((subq, models.Service.host == subq.c.host)).\
        order_by(sort_value).\
        all()


@require_admin_context
def service_get_all_share_sorted(context):
    session = get_session()
    with session.begin():
        topic = CONF.share_topic
        label = 'share_gigabytes'
        subq = model_query(context, models.Share,
                           func.sum(models.Share.size).label(label),
                           session=session, read_deleted="no").\
            join(models.ShareInstance,
                 models.ShareInstance.share_id == models.Share.id).\
            group_by(models.ShareInstance.host).\
            subquery()
        return _service_get_all_topic_subquery(context,
                                               session,
                                               topic,
                                               subq,
                                               label)


@require_admin_context
def service_get_by_args(context, host, binary):
    result = model_query(context, models.Service).\
        filter_by(host=host).\
        filter_by(binary=binary).\
        first()

    if not result:
        raise exception.HostBinaryNotFound(host=host, binary=binary)

    return result


@require_admin_context
def service_create(context, values):
    session = get_session()

    ensure_availability_zone_exists(context, values, session)

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

    ensure_availability_zone_exists(context, values, session, strict=False)

    with session.begin():
        service_ref = service_get(context, service_id, session=session)
        service_ref.update(values)
        service_ref.save(session=session)


###################


@require_context
def quota_get(context, project_id, resource, session=None):
    result = model_query(context, models.Quota, session=session,
                         read_deleted="no").\
        filter_by(project_id=project_id).\
        filter_by(resource=resource).\
        first()

    if not result:
        raise exception.ProjectQuotaNotFound(project_id=project_id)

    return result


@require_context
def quota_get_all_by_project_and_user(context, project_id, user_id):
    authorize_project_context(context, project_id)

    user_quotas = model_query(context, models.ProjectUserQuota,
                              models.ProjectUserQuota.resource,
                              models.ProjectUserQuota.hard_limit).\
        filter_by(project_id=project_id).\
        filter_by(user_id=user_id).\
        all()

    result = {'project_id': project_id, 'user_id': user_id}
    for quota in user_quotas:
        result[quota.resource] = quota.hard_limit

    return result


@require_context
def quota_get_all_by_project(context, project_id):
    authorize_project_context(context, project_id)

    rows = model_query(context, models.Quota, read_deleted="no").\
        filter_by(project_id=project_id).\
        all()

    result = {'project_id': project_id}
    for row in rows:
        result[row.resource] = row.hard_limit

    return result


@require_context
def quota_get_all(context, project_id):
    authorize_project_context(context, project_id)

    result = model_query(context, models.ProjectUserQuota).\
        filter_by(project_id=project_id).\
        all()

    return result


@require_admin_context
def quota_create(context, project_id, resource, limit, user_id=None):
    per_user = user_id and resource not in PER_PROJECT_QUOTAS

    if per_user:
        check = model_query(context, models.ProjectUserQuota).\
            filter_by(project_id=project_id).\
            filter_by(user_id=user_id).\
            filter_by(resource=resource).\
            all()
    else:
        check = model_query(context, models.Quota).\
            filter_by(project_id=project_id).\
            filter_by(resource=resource).\
            all()
    if check:
        raise exception.QuotaExists(project_id=project_id, resource=resource)

    quota_ref = models.ProjectUserQuota() if per_user else models.Quota()
    if per_user:
        quota_ref.user_id = user_id
    quota_ref.project_id = project_id
    quota_ref.resource = resource
    quota_ref.hard_limit = limit
    session = get_session()
    with session.begin():
        quota_ref.save(session)
    return quota_ref


@require_admin_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def quota_update(context, project_id, resource, limit, user_id=None):
    per_user = user_id and resource not in PER_PROJECT_QUOTAS
    model = models.ProjectUserQuota if per_user else models.Quota
    query = model_query(context, model).\
        filter_by(project_id=project_id).\
        filter_by(resource=resource)
    if per_user:
        query = query.filter_by(user_id=user_id)

    result = query.update({'hard_limit': limit})
    if not result:
        if per_user:
            raise exception.ProjectUserQuotaNotFound(project_id=project_id,
                                                     user_id=user_id)
        else:
            raise exception.ProjectQuotaNotFound(project_id=project_id)


###################


@require_context
def quota_class_get(context, class_name, resource, session=None):
    result = model_query(context, models.QuotaClass, session=session,
                         read_deleted="no").\
        filter_by(class_name=class_name).\
        filter_by(resource=resource).\
        first()

    if not result:
        raise exception.QuotaClassNotFound(class_name=class_name)

    return result


def quota_class_get_default(context):
    rows = model_query(context, models.QuotaClass, read_deleted="no").\
        filter_by(class_name=_DEFAULT_QUOTA_NAME).\
        all()

    result = {'class_name': _DEFAULT_QUOTA_NAME}
    for row in rows:
        result[row.resource] = row.hard_limit

    return result


@require_context
def quota_class_get_all_by_name(context, class_name):
    authorize_quota_class_context(context, class_name)

    rows = model_query(context, models.QuotaClass, read_deleted="no").\
        filter_by(class_name=class_name).\
        all()

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
    result = model_query(context, models.QuotaClass, read_deleted="no").\
        filter_by(class_name=class_name).\
        filter_by(resource=resource).\
        update({'hard_limit': limit})

    if not result:
        raise exception.QuotaClassNotFound(class_name=class_name)


###################


@require_context
def quota_usage_get(context, project_id, resource, user_id=None):
    query = model_query(context, models.QuotaUsage, read_deleted="no").\
        filter_by(project_id=project_id).\
        filter_by(resource=resource)
    if user_id:
        if resource not in PER_PROJECT_QUOTAS:
            result = query.filter_by(user_id=user_id).first()
        else:
            result = query.filter_by(user_id=None).first()
    else:
        result = query.first()

    if not result:
        raise exception.QuotaUsageNotFound(project_id=project_id)

    return result


def _quota_usage_get_all(context, project_id, user_id=None):
    authorize_project_context(context, project_id)
    query = model_query(context, models.QuotaUsage, read_deleted="no").\
        filter_by(project_id=project_id)
    result = {'project_id': project_id}
    if user_id:
        query = query.filter(or_(models.QuotaUsage.user_id == user_id,
                                 models.QuotaUsage.user_id is None))
        result['user_id'] = user_id

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


def _quota_usage_create(context, project_id, user_id, resource, in_use,
                        reserved, until_refresh, session=None):
    quota_usage_ref = models.QuotaUsage()
    quota_usage_ref.project_id = project_id
    quota_usage_ref.user_id = user_id
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
                       reserved, until_refresh):
    session = get_session()
    return _quota_usage_create(context, project_id, user_id, resource, in_use,
                               reserved, until_refresh, session)


@require_admin_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def quota_usage_update(context, project_id, user_id, resource, **kwargs):
    updates = {}

    for key in ['in_use', 'reserved', 'until_refresh']:
        if key in kwargs:
            updates[key] = kwargs[key]

    result = model_query(context, models.QuotaUsage, read_deleted="no").\
        filter_by(project_id=project_id).\
        filter_by(resource=resource).\
        filter(or_(models.QuotaUsage.user_id == user_id,
                   models.QuotaUsage.user_id is None)).\
        update(updates)

    if not result:
        raise exception.QuotaUsageNotFound(project_id=project_id)


###################


@require_context
def reservation_get(context, uuid, session=None):
    result = model_query(context, models.Reservation, session=session,
                         read_deleted="no").\
        filter_by(uuid=uuid).first()

    if not result:
        raise exception.ReservationNotFound(uuid=uuid)

    return result


@require_admin_context
def reservation_create(context, uuid, usage, project_id, user_id, resource,
                       delta, expire):
    return _reservation_create(context, uuid, usage, project_id, user_id,
                               resource, delta, expire)


def _reservation_create(context, uuid, usage, project_id, user_id, resource,
                        delta, expire, session=None):
    reservation_ref = models.Reservation()
    reservation_ref.uuid = uuid
    reservation_ref.usage_id = usage['id']
    reservation_ref.project_id = project_id
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

def _get_user_quota_usages(context, session, project_id, user_id):
    # Broken out for testability
    rows = model_query(context, models.QuotaUsage,
                       read_deleted="no",
                       session=session).\
        filter_by(project_id=project_id).\
        filter(or_(models.QuotaUsage.user_id == user_id,
                   models.QuotaUsage.user_id is None)).\
        with_lockmode('update').\
        all()
    return {row.resource: row for row in rows}


def _get_project_quota_usages(context, session, project_id):
    rows = model_query(context, models.QuotaUsage,
                       read_deleted="no",
                       session=session).\
        filter_by(project_id=project_id).\
        with_lockmode('update').\
        all()
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
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def quota_reserve(context, resources, project_quotas, user_quotas, deltas,
                  expire, until_refresh, max_age, project_id=None,
                  user_id=None):
    elevated = context.elevated()
    session = get_session()
    with session.begin():

        if project_id is None:
            project_id = context.project_id
        if user_id is None:
            user_id = context.user_id

        # Get the current usages
        user_usages = _get_user_quota_usages(context, session,
                                             project_id, user_id)
        project_usages = _get_project_quota_usages(context, session,
                                                   project_id)

        # Handle usage refresh
        work = set(deltas.keys())
        while work:
            resource = work.pop()

            # Do we need to refresh the usage?
            refresh = False
            if ((resource not in PER_PROJECT_QUOTAS) and
                    (resource not in user_usages)):
                user_usages[resource] = _quota_usage_create(
                    elevated,
                    project_id,
                    user_id,
                    resource,
                    0, 0,
                    until_refresh or None,
                    session=session)
                refresh = True
            elif ((resource in PER_PROJECT_QUOTAS) and
                    (resource not in user_usages)):
                user_usages[resource] = _quota_usage_create(
                    elevated,
                    project_id,
                    None,
                    resource,
                    0, 0,
                    until_refresh or None,
                    session=session)
                refresh = True
            elif user_usages[resource].in_use < 0:
                # Negative in_use count indicates a desync, so try to
                # heal from that...
                refresh = True
            elif user_usages[resource].until_refresh is not None:
                user_usages[resource].until_refresh -= 1
                if user_usages[resource].until_refresh <= 0:
                    refresh = True
            elif max_age and (user_usages[resource].updated_at -
                              timeutils.utcnow()).seconds >= max_age:
                refresh = True

            # OK, refresh the usage
            if refresh:
                # Grab the sync routine
                sync = QUOTA_SYNC_FUNCTIONS[resources[resource].sync]

                updates = sync(elevated, project_id, user_id, session)
                for res, in_use in updates.items():
                    # Make sure we have a destination for the usage!
                    if ((res not in PER_PROJECT_QUOTAS) and
                            (res not in user_usages)):
                        user_usages[res] = _quota_usage_create(
                            elevated,
                            project_id,
                            user_id,
                            res,
                            0, 0,
                            until_refresh or None,
                            session=session)
                    if ((res in PER_PROJECT_QUOTAS) and
                            (res not in user_usages)):
                        user_usages[res] = _quota_usage_create(
                            elevated,
                            project_id,
                            None,
                            res,
                            0, 0,
                            until_refresh or None,
                            session=session)

                    if user_usages[res].in_use != in_use:
                        LOG.debug('quota_usages out of sync, updating. '
                                  'project_id: %(project_id)s, '
                                  'user_id: %(user_id)s, '
                                  'resource: %(res)s, '
                                  'tracked usage: %(tracked_use)s, '
                                  'actual usage: %(in_use)s',
                                  {'project_id': project_id,
                                   'user_id': user_id,
                                   'res': res,
                                   'tracked_use': user_usages[res].in_use,
                                   'in_use': in_use})

                    # Update the usage
                    user_usages[res].in_use = in_use
                    user_usages[res].until_refresh = until_refresh or None

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
                  delta + user_usages[res].in_use < 0]

        # Now, let's check the quotas
        # NOTE(Vek): We're only concerned about positive increments.
        #            If a project has gone over quota, we want them to
        #            be able to reduce their usage without any
        #            problems.
        for key, value in user_usages.items():
            if key not in project_usages:
                project_usages[key] = value
        overs = [res for res, delta in deltas.items()
                 if user_quotas[res] >= 0 and delta >= 0 and
                 (project_quotas[res] < delta +
                  project_usages[res]['total'] or
                  user_quotas[res] < delta +
                  user_usages[res].total)]

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
                                                  user_usages[res],
                                                  project_id,
                                                  user_id,
                                                  res, delta, expire,
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
                    user_usages[res].reserved += delta

        # Apply updates to the usages table
        for usage_ref in user_usages.values():
            session.add(usage_ref)

    if unders:
        LOG.warning(_LW("Change will make usage less than 0 for the following "
                        "resources: %s"), unders)
    if overs:
        if project_quotas == user_quotas:
            usages = project_usages
        else:
            usages = user_usages
        usages = {k: dict(in_use=v['in_use'], reserved=v['reserved'])
                  for k, v in usages.items()}
        raise exception.OverQuota(overs=sorted(overs), quotas=user_quotas,
                                  usages=usages)

    return reservations


def _quota_reservations_query(session, context, reservations):
    """Return the relevant reservations."""

    # Get the listed reservations
    return model_query(context, models.Reservation,
                       read_deleted="no",
                       session=session).\
        filter(models.Reservation.uuid.in_(reservations)).\
        with_lockmode('update')


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def reservation_commit(context, reservations, project_id=None, user_id=None):
    session = get_session()
    with session.begin():
        usages = _get_user_quota_usages(context, session, project_id, user_id)
        reservation_query = _quota_reservations_query(session, context,
                                                      reservations)
        for reservation in reservation_query.all():
            usage = usages[reservation.resource]
            if reservation.delta >= 0:
                usage.reserved -= reservation.delta
            usage.in_use += reservation.delta
        reservation_query.soft_delete(synchronize_session=False)


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def reservation_rollback(context, reservations, project_id=None, user_id=None):
    session = get_session()
    with session.begin():
        usages = _get_user_quota_usages(context, session, project_id, user_id)
        reservation_query = _quota_reservations_query(session, context,
                                                      reservations)
        for reservation in reservation_query.all():
            usage = usages[reservation.resource]
            if reservation.delta >= 0:
                usage.reserved -= reservation.delta
        reservation_query.soft_delete(synchronize_session=False)


@require_admin_context
def quota_destroy_all_by_project_and_user(context, project_id, user_id):
    session = get_session()
    with session.begin():
        model_query(context, models.ProjectUserQuota, session=session,
                    read_deleted="no").\
            filter_by(project_id=project_id).\
            filter_by(user_id=user_id).soft_delete(synchronize_session=False)

        model_query(context, models.QuotaUsage,
                    session=session, read_deleted="no").\
            filter_by(project_id=project_id).\
            filter_by(user_id=user_id).soft_delete(synchronize_session=False)

        model_query(context, models.Reservation,
                    session=session, read_deleted="no").\
            filter_by(project_id=project_id).\
            filter_by(user_id=user_id).soft_delete(synchronize_session=False)


@require_admin_context
def quota_destroy_all_by_project(context, project_id):
    session = get_session()
    with session.begin():
        model_query(context, models.Quota, session=session,
                    read_deleted="no").\
            filter_by(project_id=project_id).\
            soft_delete(synchronize_session=False)

        model_query(context, models.ProjectUserQuota, session=session,
                    read_deleted="no").\
            filter_by(project_id=project_id).\
            soft_delete(synchronize_session=False)

        model_query(context, models.QuotaUsage,
                    session=session, read_deleted="no").\
            filter_by(project_id=project_id).\
            soft_delete(synchronize_session=False)

        model_query(context, models.Reservation,
                    session=session, read_deleted="no").\
            filter_by(project_id=project_id).\
            soft_delete(synchronize_session=False)


@require_admin_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def reservation_expire(context):
    session = get_session()
    with session.begin():
        current_time = timeutils.utcnow()
        reservation_query = model_query(context, models.Reservation,
                                        session=session, read_deleted="no").\
            filter(models.Reservation.expire < current_time)

        for reservation in reservation_query.join(models.QuotaUsage).all():
            if reservation.delta >= 0:
                reservation.usage.reserved -= reservation.delta
                session.add(reservation.usage)

        reservation_query.soft_delete(synchronize_session=False)


################

def extract_instance_values(values, fields):
    instance_values = {}
    for field in fields:
        field_value = values.pop(field, None)
        if field_value:
            instance_values.update({field: field_value})

    return instance_values


def extract_share_instance_values(values):
    share_instance_model_fields = [
        'status', 'host', 'scheduled_at', 'launched_at', 'terminated_at',
        'share_server_id', 'share_network_id', 'availability_zone'
    ]
    return extract_instance_values(values, share_instance_model_fields)


def extract_snapshot_instance_values(values):
    fields = ['status', 'progress', 'provider_location']
    return extract_instance_values(values, fields)


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
    ensure_availability_zone_exists(context, values, session, strict=False)
    with session.begin():
        instance_ref = _share_instance_update(
            context, share_instance_id, values, session
        )
        if with_share_data:
            parent_share = share_get(context, instance_ref['share_id'],
                                     session=session)
            instance_ref.set_share_data(parent_share)
        return instance_ref


@require_context
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
    ).first()
    if result is None:
        raise exception.NotFound()

    if with_share_data:
        parent_share = share_get(context, result['share_id'], session=session)
        result.set_share_data(parent_share)

    return result


@require_admin_context
def share_instances_get_all(context):
    session = get_session()
    return model_query(
        context, models.ShareInstance, session=session, read_deleted="no",
    ).options(
        joinedload('export_locations'),
    ).all()


@require_context
def share_instance_delete(context, instance_id, session=None):
    if session is None:
        session = get_session()

    with session.begin():
        share_export_locations_update(context, instance_id, [], delete=True)
        instance_ref = share_instance_get(context, instance_id,
                                          session=session)
        instance_ref.soft_delete(session=session, update_status=True)
        share = share_get(context, instance_ref['share_id'], session=session)
        if len(share.instances) == 0:
            share.soft_delete(session=session)
            share_access_delete_all_by_share(context, share['id'])


@require_admin_context
def share_instances_get_all_by_host(context, host):
    """Retrieves all share instances hosted on a host."""
    result = (
        model_query(context, models.ShareInstance).filter(
            or_(
                models.ShareInstance.host == host,
                models.ShareInstance.host.like("{0}#%".format(host))
            )
        ).all()
    )
    return result


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
def share_instances_get_all_by_consistency_group_id(context, cg_id):
    """Returns list of share instances that belong to given cg."""
    result = (
        model_query(context, models.Share).filter(
            models.Share.consistency_group_id == cg_id,
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
def share_replicas_get_active_replicas_by_share(context, share_id,
                                                with_share_data=False,
                                                with_share_server=False,
                                                session=None):
    """Returns all active replicas for a given share."""
    session = session or get_session()

    result = _share_replica_get_with_filters(
        context, with_share_server=with_share_server, share_id=share_id,
        replica_state=constants.REPLICA_STATE_ACTIVE, session=session).all()

    if with_share_data:
        result = _set_replica_share_data(context, result, session)

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
        ensure_availability_zone_exists(context, values, session, strict=False)
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
    return model_query(context, models.Share, session=session).\
        options(joinedload('share_metadata')).\
        options(joinedload('share_type'))


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
def share_create(context, values, create_share_instance=True):
    values = ensure_model_dict_has_id(values)
    values['share_metadata'] = _metadata_refs(values.get('metadata'),
                                              models.ShareMetadata)
    session = get_session()
    share_ref = models.Share()
    share_instance_values = extract_share_instance_values(values)
    ensure_availability_zone_exists(context, share_instance_values, session,
                                    strict=False)
    share_ref.update(values)

    with session.begin():
        share_ref.save(session=session)

        if create_share_instance:
            _share_instance_create(context, share_ref['id'],
                                   share_instance_values, session=session)

        # NOTE(u_glide): Do so to prevent errors with relationships
        return share_get(context, share_ref['id'], session=session)


@require_admin_context
def share_data_get_for_project(context, project_id, user_id, session=None):
    query = model_query(context, models.Share,
                        func.count(models.Share.id),
                        func.sum(models.Share.size),
                        read_deleted="no",
                        session=session).\
        filter_by(project_id=project_id)
    if user_id:
        result = query.filter_by(user_id=user_id).first()
    else:
        result = query.first()

    return (result[0] or 0, result[1] or 0)


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def share_update(context, share_id, values):
    session = get_session()

    share_instance_values = extract_share_instance_values(values)
    ensure_availability_zone_exists(context, share_instance_values, session,
                                    strict=False)

    with session.begin():
        share_ref = share_get(context, share_id, session=session)

        _share_instance_update(context, share_ref.instance['id'],
                               share_instance_values, session=session)

        share_ref.update(values)
        share_ref.save(session=session)
        return share_ref


@require_context
def share_get(context, share_id, session=None):
    result = _share_get_query(context, session).filter_by(id=share_id).first()

    if result is None:
        raise exception.NotFound()

    return result


@require_context
def _share_get_all_with_filters(context, project_id=None, share_server_id=None,
                                consistency_group_id=None, filters=None,
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

    if consistency_group_id:
        query = query.filter(
            models.Share.consistency_group_id == consistency_group_id)

    # Apply filters
    if not filters:
        filters = {}
    if 'metadata' in filters:
        for k, v in filters['metadata'].items():
            query = query.filter(
                or_(models.Share.share_metadata.any(  # pylint: disable=E1101
                    key=k, value=v)))
    if 'extra_specs' in filters:
        query = query.join(
            models.ShareTypeExtraSpecs,
            models.ShareTypeExtraSpecs.share_type_id ==
            models.Share.share_type_id)
        for k, v in filters['extra_specs'].items():
            query = query.filter(or_(models.ShareTypeExtraSpecs.key == k,
                                     models.ShareTypeExtraSpecs.value == v))

    # Apply sorting
    if sort_dir.lower() not in ('desc', 'asc'):
        msg = _("Wrong sorting data provided: sort key is '%(sort_key)s' "
                "and sort direction is '%(sort_dir)s'.") % {
                    "sort_key": sort_key, "sort_dir": sort_dir}
        raise exception.InvalidInput(reason=msg)

    def apply_sorting(model, query):
        sort_attr = getattr(model, sort_key)
        sort_method = getattr(sort_attr, sort_dir.lower())
        return query.order_by(sort_method())

    try:
        query = apply_sorting(models.Share, query)
    except AttributeError:
        try:
            query = apply_sorting(models.ShareInstance, query)
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
def share_get_all_by_consistency_group_id(context, cg_id,
                                          filters=None, sort_key=None,
                                          sort_dir=None):
    """Returns list of shares with given CG ID."""
    query = _share_get_all_with_filters(
        context, consistency_group_id=cg_id,
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

        session.query(models.ShareMetadata).\
            filter_by(share_id=share_id).soft_delete()


###################


def _share_access_get_query(context, session, values, read_deleted='no'):
    """Get access record."""
    query = model_query(context, models.ShareAccessMapping, session=session,
                        read_deleted=read_deleted)
    return query.filter_by(**values)


def _share_instance_access_query(context, session, access_id=None,
                                 instance_id=None):
    filters = {}

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


def share_instance_access_copy(context, share_id, instance_id, session=None):
    """Copy access rules from share to share instance."""
    session = session or get_session()

    share_access_rules = share_access_get_all_for_share(
        context, share_id, session=session)
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
def share_access_get(context, access_id):
    """Get access record."""
    session = get_session()

    access = _share_access_get_query(
        context, session, {'id': access_id}).first()
    if access:
        return access
    else:
        raise exception.NotFound()


@require_context
def share_instance_access_get(context, access_id, instance_id):
    """Get access record."""
    session = get_session()

    access = _share_instance_access_query(context, session, access_id,
                                          instance_id).first()
    if access:
        return access
    else:
        raise exception.NotFound()


@require_context
def share_access_get_all_for_share(context, share_id, session=None):
    session = session or get_session()
    return _share_access_get_query(context, session,
                                   {'share_id': share_id}).all()


@require_context
def share_access_get_all_for_instance(context, instance_id, session=None):
    """Get all access rules related to a certain share instance."""
    session = get_session()
    return _share_access_get_query(context, session, {}).join(
        models.ShareInstanceAccessMapping,
        models.ShareInstanceAccessMapping.access_id ==
        models.ShareAccessMapping.id).filter(
        models.ShareInstanceAccessMapping.share_instance_id ==
        instance_id).all()


@require_context
def share_instance_access_get_all(context, access_id, session=None):
    if not session:
        session = get_session()
    return _share_instance_access_query(context, session, access_id).all()


@require_context
def share_access_get_all_by_type_and_access(context, share_id, access_type,
                                            access):
    session = get_session()
    return _share_access_get_query(context, session,
                                   {'share_id': share_id,
                                    'access_type': access_type,
                                    'access_to': access}).all()


@require_context
def share_access_delete(context, access_id):
    session = get_session()

    with session.begin():
        mappings = share_instance_access_get_all(context, access_id, session)

        if len(mappings) > 0:
            msg = (_("Access rule %s has mappings"
                     " to share instances.") % access_id)
            raise exception.InvalidShareAccess(msg)

        session.query(models.ShareAccessMapping).\
            filter_by(id=access_id).soft_delete()


@require_context
def share_access_delete_all_by_share(context, share_id):
    session = get_session()
    with session.begin():
        session.query(models.ShareAccessMapping). \
            filter_by(share_id=share_id).soft_delete()


@require_context
def share_instance_access_delete(context, mapping_id):
    session = get_session()
    with session.begin():

        mapping = session.query(models.ShareInstanceAccessMapping).\
            filter_by(id=mapping_id).first()

        if not mapping:
            exception.NotFound()

        mapping.soft_delete(session)

        other_mappings = share_instance_access_get_all(
            context, mapping['access_id'], session)

        # NOTE(u_glide): Remove access rule if all mappings were removed.
        if len(other_mappings) == 0:
            (
                session.query(models.ShareAccessMapping)
                .filter_by(id=mapping['access_id'])
                .soft_delete()
            )


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def share_instance_update_access_status(context, share_instance_id, status):
    session = get_session()
    with session.begin():
        mapping = session.query(models.ShareInstance).\
            filter_by(id=share_instance_id).first()
        mapping.update({'access_rules_status': status})
        mapping.save(session=session)
        return mapping


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
def share_snapshot_create(context, values, create_snapshot_instance=True):
    values = ensure_model_dict_has_id(values)

    snapshot_ref = models.ShareSnapshot()
    snapshot_instance_values = extract_snapshot_instance_values(values)
    share_ref = share_get(context, values.get('share_id'))
    snapshot_instance_values.update(
        {'share_instance_id': share_ref.instance.id}
    )

    snapshot_ref.update(values)
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
        return share_snapshot_get(context, values['id'], session=session)


@require_admin_context
def snapshot_data_get_for_project(context, project_id, user_id, session=None):
    query = model_query(context, models.ShareSnapshot,
                        func.count(models.ShareSnapshot.id),
                        func.sum(models.ShareSnapshot.size),
                        read_deleted="no",
                        session=session).\
        filter_by(project_id=project_id)

    if user_id:
        result = query.filter_by(user_id=user_id).first()
    else:
        result = query.first()

    return (result[0] or 0, result[1] or 0)


@require_context
def share_snapshot_destroy(context, snapshot_id):
    session = get_session()
    with session.begin():
        snapshot_ref = share_snapshot_get(context, snapshot_id,
                                          session=session)

        if len(snapshot_ref.instances) > 0:
            msg = _("Snapshot %(id)s has %(count)s snapshot instances.") % {
                'id': snapshot_id, 'count': len(snapshot_ref.instances)}
            raise exception.InvalidShareSnapshot(msg)

        snapshot_ref.soft_delete(session=session)


@require_context
def share_snapshot_get(context, snapshot_id, session=None):
    result = model_query(context, models.ShareSnapshot, session=session,
                         project_only=True).\
        filter_by(id=snapshot_id).\
        options(joinedload('share')).\
        first()

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
def share_snapshot_data_get_for_project(context, project_id, session=None):
    authorize_project_context(context, project_id)
    result = model_query(context, models.ShareSnapshot,
                         func.count(models.ShareSnapshot.id),
                         func.sum(models.ShareSnapshot.share_size),
                         read_deleted="no",
                         session=session).\
        filter_by(project_id=project_id).\
        first()

    # NOTE(vish): convert None to 0
    return (result[0] or 0, result[1] or 0)


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def share_snapshot_update(context, snapshot_id, values):
    session = get_session()
    with session.begin():
        snapshot_ref = share_snapshot_get(context, snapshot_id,
                                          session=session)

        instance_values = extract_snapshot_instance_values(values)

        if values:
            snapshot_ref.update(values)
            snapshot_ref.save(session=session)

        if instance_values:
            snapshot_ref.instance.update(instance_values)
            snapshot_ref.instance.save(session=session)

        return snapshot_ref


#################################


@require_context
@require_share_exists
def share_metadata_get(context, share_id):
    return _share_metadata_get(context, share_id)


@require_context
@require_share_exists
def share_metadata_delete(context, share_id, key):
    _share_metadata_get_query(context, share_id).\
        filter_by(key=key).soft_delete()


@require_context
@require_share_exists
def share_metadata_update(context, share_id, metadata, delete):
    return _share_metadata_update(context, share_id, metadata, delete)


def _share_metadata_get_query(context, share_id, session=None):
    return model_query(context, models.ShareMetadata, session=session,
                       read_deleted="no").\
        filter_by(share_id=share_id).\
        options(joinedload('share'))


@require_context
@require_share_exists
def _share_metadata_get(context, share_id, session=None):
    rows = _share_metadata_get_query(context, share_id,
                                     session=session).all()
    result = {}
    for row in rows:
        result[row['key']] = row['value']

    return result


@require_context
@require_share_exists
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
    result = _share_metadata_get_query(context, share_id, session=session).\
        filter_by(key=key).\
        first()

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
                                           include_admin_only=True):
    share = share_get(context, share_id)
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
    result = _security_service_get_query(context, session=session).\
        filter_by(id=id).first()

    if result is None:
        raise exception.SecurityServiceNotFound(security_service_id=id)
    return result


@require_context
def security_service_get_all(context):
    return _security_service_get_query(context).all()


@require_context
def security_service_get_all_by_project(context, project_id):
    return _security_service_get_query(context).\
        filter_by(project_id=project_id).all()


def _security_service_get_query(context, session=None):
    if session is None:
        session = get_session()
    return model_query(context, models.SecurityService, session=session)


###################


def _network_get_query(context, session=None):
    if session is None:
        session = get_session()
    return model_query(context, models.ShareNetwork, session=session).\
        options(joinedload('share_instances'),
                joinedload('security_services'),
                joinedload('share_servers'))


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
def share_network_get_all_by_project(context, project_id, user_id=None,
                                     session=None):
    query = _network_get_query(context, session)
    query = query.filter_by(project_id=project_id)
    if user_id is not None:
        query = query.filter_by(user_id=user_id)
    return query.all()


@require_context
def share_network_get_all_by_security_service(context, security_service_id):
    session = get_session()
    return model_query(context, models.ShareNetwork, session=session).\
        join(models.ShareNetworkSecurityServiceAssociation,
             models.ShareNetwork.id ==
             models.ShareNetworkSecurityServiceAssociation.share_network_id).\
        filter_by(security_service_id=security_service_id, deleted=0).\
        options(joinedload('share_servers')).all()


@require_context
def share_network_add_security_service(context, id, security_service_id):
    session = get_session()

    with session.begin():
        assoc_ref = model_query(
            context,
            models.ShareNetworkSecurityServiceAssociation,
            session=session).\
            filter_by(share_network_id=id).\
            filter_by(security_service_id=security_service_id).first()

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

        assoc_ref = model_query(
            context,
            models.ShareNetworkSecurityServiceAssociation,
            session=session).\
            filter_by(share_network_id=id).\
            filter_by(security_service_id=security_service_id).first()

        if assoc_ref:
            assoc_ref.soft_delete(session)
        else:
            msg = "No association defined"
            raise exception.ShareNetworkSecurityServiceDissociationError(
                share_network_id=id,
                security_service_id=security_service_id,
                reason=msg)

    return share_nw_ref


###################


def _server_get_query(context, session=None):
    if session is None:
        session = get_session()
    return model_query(context, models.ShareServer, session=session).\
        options(joinedload('share_instances'),
                joinedload('network_allocations'),
                joinedload('share_network'))


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
    result = _server_get_query(context, session).filter_by(id=server_id)\
        .first()
    if result is None:
        raise exception.ShareServerNotFound(share_server_id=server_id)
    return result


@require_context
def share_server_get_all_by_host_and_share_net_valid(context, host,
                                                     share_net_id,
                                                     session=None):
    result = _server_get_query(context, session).filter_by(host=host)\
        .filter_by(share_network_id=share_net_id)\
        .filter(models.ShareServer.status.in_(
            (constants.STATUS_CREATING, constants.STATUS_ACTIVE))).all()
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
    result = _server_get_query(context)\
        .filter_by(host=host)\
        .filter(~models.ShareServer.consistency_groups.any())\
        .filter(~models.ShareServer.share_instances.any())\
        .filter(models.ShareServer.status.in_(valid_server_status))\
        .filter(models.ShareServer.updated_at < updated_before).all()
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
    share_server_details = model_query(context,
                                       models.ShareServerBackendDetails,
                                       session=session)\
        .filter_by(share_server_id=share_server_id).all()
    for item in share_server_details:
        item.soft_delete(session)


###################

def _driver_private_data_query(session, context, host, entity_id, key=None,
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
def driver_private_data_get(context, host, entity_id, key=None,
                            default=None, session=None):
    if not session:
        session = get_session()

    query = _driver_private_data_query(session, context, host, entity_id, key)

    if key is None or isinstance(key, list):
        return {item.key: item.value for item in query.all()}
    else:
        result = query.first()
        return result["value"] if result is not None else default


@require_context
def driver_private_data_update(context, host, entity_id, details,
                               delete_existing=False, session=None):
    # NOTE(u_glide): following code modifies details dict, that's why we should
    # copy it
    new_details = copy.deepcopy(details)

    if not session:
        session = get_session()

    with session.begin():
        # Process existing data
        # NOTE(u_glide): read_deleted=None means here 'read all'
        original_data = _driver_private_data_query(
            session, context, host, entity_id, read_deleted=None).all()

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
                "host": host,
                "entity_uuid": entity_id,
                "key": key,
                "value": six.text_type(value)
            })
            data_ref.save(session=session)

        return details


@require_context
def driver_private_data_delete(context, host, entity_id, key=None,
                               session=None):
    if not session:
        session = get_session()

    with session.begin():
        query = _driver_private_data_query(session, context, host,
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
    result = model_query(context, models.NetworkAllocation, session=session).\
        filter_by(id=id).first()
    if result is None:
        raise exception.NotFound()
    return result


@require_context
def network_allocations_get_by_ip_address(context, ip_address):
    session = get_session()
    result = model_query(context, models.NetworkAllocation, session=session).\
        filter_by(ip_address=ip_address).all()
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


def _dict_with_extra_specs(inst_type_query):
    """Convert type query result to dict with extra_spec and rate_limit.

Takes a volume type query returned by sqlalchemy and returns it
as a dictionary, converting the extra_specs entry from a list
of dicts:

'extra_specs' : [{'key': 'k1', 'value': 'v1', ...}, ...]
to a single dict:
'extra_specs' : {'k1': 'v1'}
"""
    inst_type_dict = dict(inst_type_query)
    extra_specs = {x['key']: x['value']
                   for x in inst_type_query['extra_specs']}
    inst_type_dict['extra_specs'] = extra_specs
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
    query = model_query(context,
                        models.ShareTypes,
                        session=session,
                        read_deleted=read_deleted). \
        options(joinedload('extra_specs'))

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
        result[row['name']] = _dict_with_extra_specs(row)

    return result


def _share_type_get_id_from_share_type_query(context, id, session=None):
    return model_query(
        context, models.ShareTypes, read_deleted="no", session=session).\
        filter_by(id=id)


def _share_type_get_id_from_share_type(context, id, session=None):
    result = _share_type_get_id_from_share_type_query(
        context, id, session=session).first()
    if not result:
        raise exception.ShareTypeNotFound(share_type_id=id)
    return result['id']


@require_context
def _share_type_get(context, id, session=None, inactive=False,
                    expected_fields=None):
    expected_fields = expected_fields or []
    read_deleted = "yes" if inactive else "no"
    result = _share_type_get_query(
        context, session, read_deleted, expected_fields). \
        filter_by(id=id). \
        first()

    if not result:
        raise exception.ShareTypeNotFound(share_type_id=id)

    share_type = _dict_with_extra_specs(result)

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


@require_context
def _share_type_get_by_name(context, name, session=None):
    result = model_query(context, models.ShareTypes, session=session).\
        options(joinedload('extra_specs')).\
        filter_by(name=name).\
        first()

    if not result:
        raise exception.ShareTypeNotFoundByName(share_type_name=name)

    return _dict_with_extra_specs(result)


@require_context
def share_type_get_by_name(context, name):
    """Return a dict describing specific share_type."""

    return _share_type_get_by_name(context, name)


@require_admin_context
def share_type_destroy(context, id):
    session = get_session()
    with session.begin():
        _share_type_get(context, id, session)
        results = model_query(context, models.Share, session=session,
                              read_deleted="no").\
            filter_by(share_type_id=id).count()
        cg_count = model_query(context,
                               models.ConsistencyGroupShareTypeMapping,
                               read_deleted="no",
                               session=session).\
            filter_by(share_type_id=id).count()
        if results or cg_count:
            LOG.error(_LE('ShareType %s deletion failed, ShareType in use.'),
                      id)
            raise exception.ShareTypeInUse(share_type_id=id)
        model_query(context, models.ShareTypeExtraSpecs, session=session).\
            filter_by(share_type_id=id).soft_delete()
        model_query(context, models.ShareTypes, session=session).\
            filter_by(id=id).soft_delete()


def _share_type_access_query(context, session=None):
    return model_query(context, models.ShareTypeProjects, session=session,
                       read_deleted="no")


@require_admin_context
def share_type_access_get_all(context, type_id):
    share_type_id = _share_type_get_id_from_share_type(context, type_id)
    return _share_type_access_query(context).\
        filter_by(share_type_id=share_type_id).all()


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

    count = _share_type_access_query(context).\
        filter_by(share_type_id=share_type_id).\
        filter_by(project_id=project_id).\
        soft_delete(synchronize_session=False)
    if count == 0:
        raise exception.ShareTypeAccessNotFound(
            share_type_id=type_id, project_id=project_id)


@require_context
def volume_get_active_by_window(context,
                                begin,
                                end=None,
                                project_id=None):
    """Return volumes that were active during window."""
    query = model_query(context, models.Share, read_deleted="yes")
    query = query.filter(or_(models.Share.deleted_at is None,
                             models.Share.deleted_at > begin))
    if end:
        query = query.filter(models.Share.created_at < end)
    if project_id:
        query = query.filter_by(project_id=project_id)

    return query.all()

####################


def _share_type_extra_specs_query(context, share_type_id, session=None):
    return model_query(context, models.ShareTypeExtraSpecs, session=session,
                       read_deleted="no").\
        filter_by(share_type_id=share_type_id).\
        options(joinedload('share_type'))


@require_context
def share_type_extra_specs_get(context, share_type_id):
    rows = _share_type_extra_specs_query(context, share_type_id).\
        all()

    result = {}
    for row in rows:
        result[row['key']] = row['value']

    return result


@require_context
def share_type_extra_specs_delete(context, share_type_id, key):
    session = get_session()
    with session.begin():
        _share_type_extra_specs_get_item(context, share_type_id, key, session)
        _share_type_extra_specs_query(context, share_type_id, session).\
            filter_by(key=key).soft_delete()


@require_context
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


def ensure_availability_zone_exists(context, values, session, strict=True):
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


####################


def _consistency_group_get(context, consistency_group_id, session=None):
    session = session or get_session()
    result = model_query(context, models.ConsistencyGroup,
                         session=session,
                         project_only=True,
                         read_deleted='no').\
        filter_by(id=consistency_group_id).\
        options(joinedload('share_types')).\
        first()

    if not result:
        raise exception.ConsistencyGroupNotFound(
            consistency_group_id=consistency_group_id)

    return result


@require_context
def consistency_group_get(context, consistency_group_id, session=None):
    return _consistency_group_get(context, consistency_group_id,
                                  session=session)


def _consistency_group_get_all_query(context, session=None):
    session = session or get_session()
    return model_query(context, models.ConsistencyGroup, session=session,
                       read_deleted='no')


@require_admin_context
def consistency_group_get_all(context, detailed=True):
    query = _consistency_group_get_all_query(context)
    if detailed:
        return query.options(joinedload('share_types')).all()
    else:
        query = query.with_entities(models.ConsistencyGroup.id,
                                    models.ConsistencyGroup.name)
        values = []
        for item in query.all():
            id, name = item
            values.append({"id": id, "name": name})
        return values


@require_admin_context
def consistency_group_get_all_by_host(context, host, detailed=True):
    query = _consistency_group_get_all_query(context).filter_by(host=host)
    if detailed:
        return query.options(joinedload('share_types')).all()
    else:
        query = query.with_entities(models.ConsistencyGroup.id,
                                    models.ConsistencyGroup.name)
        values = []
        for item in query.all():
            id, name = item
            values.append({"id": id, "name": name})
        return values


@require_context
def consistency_group_get_all_by_project(context, project_id, detailed=True):
    authorize_project_context(context, project_id)
    query = _consistency_group_get_all_query(context).filter_by(
        project_id=project_id)
    if detailed:
        return query.options(joinedload('share_types')).all()
    else:
        query = query.with_entities(models.ConsistencyGroup.id,
                                    models.ConsistencyGroup.name)
        values = []
        for item in query.all():
            id, name = item
            values.append({"id": id, "name": name})
        return values


@require_context
def consistency_group_get_all_by_share_server(context, share_server_id):
    return _consistency_group_get_all_query(context).filter_by(
        share_server_id=share_server_id).all()


@require_context
def consistency_group_create(context, values):
    consistency_group = models.ConsistencyGroup()
    if not values.get('id'):
        values['id'] = six.text_type(uuid.uuid4())

    mappings = []
    for item in values.get('share_types') or []:
        mapping = models.ConsistencyGroupShareTypeMapping()
        mapping['id'] = six.text_type(uuid.uuid4())
        mapping['share_type_id'] = item
        mapping['consistency_group_id'] = values['id']
        mappings.append(mapping)

    values['share_types'] = mappings

    session = get_session()
    with session.begin():
        consistency_group.update(values)
        session.add(consistency_group)

        return _consistency_group_get(context, values['id'], session=session)


@require_context
def consistency_group_update(context, consistency_group_id, values):
    session = get_session()
    with session.begin():
        cg_ref = _consistency_group_get(context, consistency_group_id,
                                        session=session)

        cg_ref.update(values)
        cg_ref.save(session=session)
        return cg_ref


@require_admin_context
def consistency_group_destroy(context, consistency_group_id):
    session = get_session()
    with session.begin():
        cg_ref = _consistency_group_get(context, consistency_group_id,
                                        session=session)
        cg_ref.soft_delete(session)

        session.query(models.ConsistencyGroupShareTypeMapping).\
            filter_by(consistency_group_id=cg_ref['id']).soft_delete()


@require_context
def count_shares_in_consistency_group(context, consistency_group_id,
                                      session=None):
    session = session or get_session()
    return model_query(
        context, models.Share, session=session,
        project_only=True, read_deleted="no").\
        filter_by(consistency_group_id=consistency_group_id).\
        count()


@require_context
def count_cgsnapshots_in_consistency_group(context, consistency_group_id,
                                           session=None):
    session = session or get_session()
    return model_query(
        context, models.CGSnapshot, session=session,
        project_only=True, read_deleted="no").\
        filter_by(consistency_group_id=consistency_group_id).\
        count()


@require_context
def count_consistency_groups_in_share_network(context, share_network_id,
                                              session=None):
    session = session or get_session()
    return model_query(
        context, models.ConsistencyGroup, session=session,
        project_only=True, read_deleted="no").\
        filter_by(share_network_id=share_network_id).\
        count()


@require_context
def count_cgsnapshot_members_in_share(context, share_id, session=None):
    session = session or get_session()
    return model_query(
        context, models.CGSnapshotMember, session=session,
        project_only=True, read_deleted="no").\
        filter_by(share_id=share_id).\
        count()


@require_context
def _cgsnapshot_get(context, cgsnapshot_id, session=None):
    session = session or get_session()
    result = model_query(context, models.CGSnapshot, session=session,
                         project_only=True, read_deleted='no').\
        options(joinedload('cgsnapshot_members')).\
        options(joinedload('consistency_group')).\
        filter_by(id=cgsnapshot_id).\
        first()

    if not result:
        raise exception.CGSnapshotNotFound(cgsnapshot_id=cgsnapshot_id)

    return result


def _cgsnapshot_get_all_query(context, session=None):
    session = session or get_session()
    return model_query(context, models.CGSnapshot, session=session,
                       reade_deleted='no').\
        options(joinedload('cgsnapshot_members')).\
        options(joinedload('consistency_group'))


@require_context
def cgsnapshot_get(context, cgsnapshot_id, session=None):
    session = session or get_session()
    return _cgsnapshot_get(context, cgsnapshot_id, session=session)


@require_admin_context
def cgsnapshot_get_all(context, detailed=True):
    query = _cgsnapshot_get_all_query(context)
    if detailed:
        return query.all()
    else:
        query = query.with_entities(models.CGSnapshot.id,
                                    models.CGSnapshot.name)
        values = []
        for item in query.all():
            id, name = item
            values.append({"id": id, "name": name})
        return values


@require_context
def cgsnapshot_get_all_by_project(context, project_id, detailed=True):
    authorize_project_context(context, project_id)
    query = _cgsnapshot_get_all_query(context).filter_by(
        project_id=project_id)
    if detailed:
        return query.all()
    else:
        query = query.with_entities(models.CGSnapshot.id,
                                    models.CGSnapshot.name)
        values = []
        for item in query.all():
            id, name = item
            values.append({"id": id, "name": name})
        return values


@require_context
def cgsnapshot_create(context, values):
    cgsnapshot = models.CGSnapshot()
    if not values.get('id'):
        values['id'] = six.text_type(uuid.uuid4())

    session = get_session()
    with session.begin():
        cgsnapshot.update(values)
        session.add(cgsnapshot)

        return _cgsnapshot_get(context, values['id'], session=session)


@require_context
def cgsnapshot_update(context, cgsnapshot_id, values):
    session = get_session()
    with session.begin():
        cg_ref = _cgsnapshot_get(context, cgsnapshot_id, session=session)

        cg_ref.update(values)
        cg_ref.save(session=session)
        return cg_ref


@require_admin_context
def cgsnapshot_destroy(context, cgsnapshot_id):
    session = get_session()
    with session.begin():
        cgsnap_ref = _cgsnapshot_get(context, cgsnapshot_id, session=session)
        cgsnap_ref.soft_delete(session)

        session.query(models.CGSnapshotMember).\
            filter_by(cgsnapshot_id=cgsnapshot_id).soft_delete()


@require_context
def cgsnapshot_members_get_all(context, cgsnapshot_id, session=None):
    session = session or get_session()
    query = model_query(context, models.CGSnapshotMember,
                        session=session, read_deleted='no').filter_by(
        cgsnapshot_id=cgsnapshot_id)
    return query.all()


@require_context
def cgsnapshot_member_get(context, member_id, session=None):
    result = model_query(context, models.CGSnapshotMember, session=session,
                         project_only=True, read_deleted='no').\
        filter_by(id=member_id).\
        first()

    if not result:
        raise exception.CGSnapshotMemberNotFound(member_id=member_id)

    return result


@require_context
def cgsnapshot_member_create(context, values):
    member = models.CGSnapshotMember()
    if not values.get('id'):
        values['id'] = six.text_type(uuid.uuid4())

    session = get_session()
    with session.begin():
        member.update(values)
        session.add(member)

        return cgsnapshot_member_get(context, values['id'], session=session)


@require_context
def cgsnapshot_member_update(context, member_id, values):
    session = get_session()
    with session.begin():
        member = cgsnapshot_member_get(context, member_id, session=session)
        member.update(values)
        session.add(member)

        return cgsnapshot_member_get(context, member_id, session=session)
