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

from oslo_config import cfg
from oslo_db import exception as db_exception
from oslo_log import log
from oslo_utils import uuidutils

from manila.common import constants
from manila import context
from manila import db
from manila import exception
from manila.i18n import _

CONF = cfg.CONF
LOG = log.getLogger(__name__)


def create(context, name, share_types, group_specs=None, is_public=True,
           projects=None):
    """Creates share group types."""
    group_specs = group_specs or {}
    projects = projects or []
    try:
        type_ref = db.share_group_type_create(
            context,
            {"name": name, "group_specs": group_specs, "is_public": is_public,
             "share_types": share_types},
            projects=projects)
    except db_exception.DBError:
        LOG.exception('DB error')
        raise exception.ShareGroupTypeCreateFailed(
            name=name, group_specs=group_specs)
    return type_ref


def destroy(context, type_id):
    """Marks share group types as deleted."""
    if id is None:
        msg = _("Share group type ID cannot be None.")
        raise exception.InvalidShareGroupType(reason=msg)
    else:
        db.share_group_type_destroy(context, type_id)


def get_all(context, inactive=0, search_opts=None):
    """Get all non-deleted share group types."""
    # TODO(ameade): Fix docstring
    search_opts = search_opts or {}
    filters = {}

    if 'is_public' in search_opts:
        filters['is_public'] = search_opts.pop('is_public')

    share_group_types = db.share_group_type_get_all(
        context, inactive, filters=filters)

    if search_opts:
        LOG.debug("Searching by: %s", search_opts)

        def _check_group_specs_match(share_group_type, searchdict):
            for k, v in searchdict.items():
                if (k not in share_group_type['group_specs'].keys()
                        or share_group_type['group_specs'][k] != v):
                    return False
            return True

        # search_option to filter_name mapping.
        filter_mapping = {'group_specs': _check_group_specs_match}

        result = {}
        for type_name, type_args in share_group_types.items():
            # go over all filters in the list
            for opt, values in search_opts.items():
                try:
                    filter_func = filter_mapping[opt]
                except KeyError:
                    # no such filter - ignore it, go to next filter
                    continue
                else:
                    if filter_func(type_args, values):
                        result[type_name] = type_args
                        break
        share_group_types = result
    return share_group_types


def get(ctxt, type_id, expected_fields=None):
    """Retrieves single share group type by id."""
    if type_id is None:
        msg = _("Share type ID cannot be None.")
        raise exception.InvalidShareGroupType(reason=msg)

    if ctxt is None:
        ctxt = context.get_admin_context()

    return db.share_group_type_get(
        ctxt, type_id, expected_fields=expected_fields)


def get_by_name(context, name):
    """Retrieves single share group type by name."""
    if name is None:
        msg = _("name cannot be None.")
        raise exception.InvalidShareGroupType(reason=msg)

    return db.share_group_type_get_by_name(context, name)


def get_by_name_or_id(context, share_group_type=None):
    if not share_group_type:
        share_group_type_ref = get_default(context)
        if not share_group_type_ref:
            msg = _("Default share group type not found.")
            raise exception.ShareGroupTypeNotFound(reason=msg)
        return share_group_type_ref

    if uuidutils.is_uuid_like(share_group_type):
        return get(context, share_group_type)
    else:
        return get_by_name(context, share_group_type)


def get_default(ctxt=None):
    """Get the default share group type."""
    name = CONF.default_share_group_type
    if name is None:
        return {}
    if ctxt is None:
        ctxt = context.get_admin_context()
    try:
        return get_by_name(ctxt, name)
    except exception.ShareGroupTypeNotFoundByName:
        LOG.exception(
            "Default share group type '%s' is not found, "
            "please check 'default_share_group_type' config.",
            name,
        )


def get_tenant_visible_group_specs():
    return constants.ExtraSpecs.TENANT_VISIBLE


def get_boolean_group_specs():
    return constants.ExtraSpecs.BOOLEAN


def add_share_group_type_access(context, share_group_type_id, project_id):
    """Add access to share group type for project_id."""
    if share_group_type_id is None:
        msg = _("share_group_type_id cannot be None.")
        raise exception.InvalidShareGroupType(reason=msg)
    return db.share_group_type_access_add(
        context, share_group_type_id, project_id)


def remove_share_group_type_access(context, share_group_type_id, project_id):
    """Remove access to share group type for project_id."""
    if share_group_type_id is None:
        msg = _("share_group_type_id cannot be None.")
        raise exception.InvalidShareGroupType(reason=msg)
    return db.share_group_type_access_remove(
        context, share_group_type_id, project_id)
