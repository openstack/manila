# Copyright (c) 2014 OpenStack Foundation.
# Copyright (c) 2015 Tom Barron.  All rights reserved.
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

"""Built-in share type properties."""

import re

from oslo_config import cfg
from oslo_db import exception as db_exception
from oslo_log import log
from oslo_utils import strutils
from oslo_utils import uuidutils
import six

from manila.common import constants
from manila import context
from manila import db
from manila import exception
from manila.i18n import _
from manila.i18n import _LE

CONF = cfg.CONF
LOG = log.getLogger(__name__)


def create(context, name, extra_specs=None, is_public=True, projects=None):
    """Creates share types."""
    extra_specs = extra_specs or {}
    projects = projects or []

    if constants.ExtraSpecs.SNAPSHOT_SUPPORT not in list(extra_specs):
        extra_specs[constants.ExtraSpecs.SNAPSHOT_SUPPORT] = 'True'

    try:
        get_valid_required_extra_specs(extra_specs)
    except exception.InvalidExtraSpec as e:
        raise exception.InvalidShareType(reason=six.text_type(e))

    try:
        type_ref = db.share_type_create(context,
                                        dict(name=name,
                                             extra_specs=extra_specs,
                                             is_public=is_public),
                                        projects=projects)
    except db_exception.DBError as e:
        LOG.exception(_LE('DB error: %s'), e)
        raise exception.ShareTypeCreateFailed(name=name,
                                              extra_specs=extra_specs)
    return type_ref


def destroy(context, id):
    """Marks share types as deleted."""
    if id is None:
        msg = _("id cannot be None")
        raise exception.InvalidShareType(reason=msg)
    else:
        db.share_type_destroy(context, id)


def get_all_types(context, inactive=0, search_opts=None):
    """Get all non-deleted share_types.

    """
    search_opts = search_opts or {}
    filters = {}

    if 'is_public' in search_opts:
        filters['is_public'] = search_opts.pop('is_public')

    share_types = db.share_type_get_all(context, inactive, filters=filters)

    for type_name, type_args in share_types.items():
        required_extra_specs = {}
        try:
            required_extra_specs = get_valid_required_extra_specs(
                type_args['extra_specs'])
        except exception.InvalidExtraSpec as e:
            values = {
                'share_type': type_name,
                'error': six.text_type(e)
            }
            LOG.exception(_LE('Share type %(share_type)s has invalid required'
                              ' extra specs: %(error)s'), values)

        type_args['required_extra_specs'] = required_extra_specs

    if search_opts:
        LOG.debug("Searching by: %s", search_opts)

        def _check_extra_specs_match(share_type, searchdict):
            for k, v in searchdict.items():
                if (k not in share_type['extra_specs'].keys()
                        or share_type['extra_specs'][k] != v):
                    return False
            return True

        # search_option to filter_name mapping.
        filter_mapping = {'extra_specs': _check_extra_specs_match}

        result = {}
        for type_name, type_args in share_types.items():
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
        share_types = result
    return share_types


def get_share_type(ctxt, id, expected_fields=None):
    """Retrieves single share type by id."""
    if id is None:
        msg = _("id cannot be None")
        raise exception.InvalidShareType(reason=msg)

    if ctxt is None:
        ctxt = context.get_admin_context()

    return db.share_type_get(ctxt, id, expected_fields=expected_fields)


def get_share_type_by_name(context, name):
    """Retrieves single share type by name."""
    if name is None:
        msg = _("name cannot be None")
        raise exception.InvalidShareType(reason=msg)

    return db.share_type_get_by_name(context, name)


def get_share_type_by_name_or_id(context, share_type=None):
    if not share_type:
        share_type_ref = get_default_share_type(context)
        if not share_type_ref:
            msg = _("Default share type not found")
            raise exception.ShareTypeNotFound(reason=msg)
        return share_type_ref

    if uuidutils.is_uuid_like(share_type):
        return get_share_type(context, share_type)
    else:
        return get_share_type_by_name(context, share_type)


def get_default_share_type(ctxt=None):
    """Get the default share type."""
    name = CONF.default_share_type

    if name is None:
        return {}

    if ctxt is None:
        ctxt = context.get_admin_context()

    try:
        return get_share_type_by_name(ctxt, name)
    except exception.ShareTypeNotFoundByName as e:
        # Couldn't find share type with the name in default_share_type
        # flag, record this issue and move on
        # TODO(zhiteng) consider add notification to warn admin
        LOG.exception(_LE('Default share type is not found, '
                          'please check default_share_type config: %s'),
                      e)


def get_share_type_extra_specs(share_type_id, key=False):
    share_type = get_share_type(context.get_admin_context(),
                                share_type_id)
    extra_specs = share_type['extra_specs']
    if key:
        if extra_specs.get(key):
            return extra_specs.get(key)
        else:
            return False
    else:
        return extra_specs


def get_required_extra_specs():
    return constants.ExtraSpecs.REQUIRED


def get_undeletable_extra_specs():
    return constants.ExtraSpecs.UNDELETABLE


def get_tenant_visible_extra_specs():
    return constants.ExtraSpecs.TENANT_VISIBLE


def get_boolean_extra_specs():
    return constants.ExtraSpecs.BOOLEAN


def is_valid_required_extra_spec(key, value):
    """Validates required extra_spec value.

    :param key: extra_spec name
    :param value: extra_spec value
    :return: None if provided extra_spec is not required
             True/False if extra_spec is required and valid or not.
    """
    if key not in get_required_extra_specs():
        return

    if key == constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS:
        return strutils.bool_from_string(value, default=None) is not None

    return False


def get_valid_required_extra_specs(extra_specs):
    """Returns required extra specs from dict.

    Returns None if extra specs are not valid, or if
    some required extras specs is missed.
    """
    extra_specs = extra_specs or {}

    missed_extra_specs = set(get_required_extra_specs()) - set(extra_specs)

    if missed_extra_specs:
        specs = ",".join(missed_extra_specs)
        msg = _("Required extra specs '%s' not specified.") % specs
        raise exception.InvalidExtraSpec(reason=msg)

    required_extra_specs = {}

    for k in get_required_extra_specs():
        value = extra_specs.get(k, '')
        if not is_valid_required_extra_spec(k, value):
            msg = _("Value of required extra_spec %s is not valid") % k
            raise exception.InvalidExtraSpec(reason=msg)

        required_extra_specs[k] = value

    return required_extra_specs


def add_share_type_access(context, share_type_id, project_id):
    """Add access to share type for project_id."""
    if share_type_id is None:
        msg = _("share_type_id cannot be None")
        raise exception.InvalidShareType(reason=msg)
    return db.share_type_access_add(context, share_type_id, project_id)


def remove_share_type_access(context, share_type_id, project_id):
    """Remove access to share type for project_id."""
    if share_type_id is None:
        msg = _("share_type_id cannot be None")
        raise exception.InvalidShareType(reason=msg)
    return db.share_type_access_remove(context, share_type_id, project_id)


def share_types_diff(context, share_type_id1, share_type_id2):
    """Returns a 'diff' of two share types and whether they are equal.

    Returns a tuple of (diff, equal), where 'equal' is a boolean indicating
    whether there is any difference, and 'diff' is a dictionary with the
    following format:
    {'extra_specs': {
    'key1': (value_in_1st_share_type, value_in_2nd_share_type),
    'key2': (value_in_1st_share_type, value_in_2nd_share_type),
    ...}
    """

    def _dict_diff(dict1, dict2):
        res = {}
        equal = True
        if dict1 is None:
            dict1 = {}
        if dict2 is None:
            dict2 = {}
        for k, v in dict1.items():
            res[k] = (v, dict2.get(k))
            if k not in dict2 or res[k][0] != res[k][1]:
                equal = False
        for k, v in dict2.items():
            res[k] = (dict1.get(k), v)
            if k not in dict1 or res[k][0] != res[k][1]:
                equal = False
        return (res, equal)

    all_equal = True
    diff = {}
    share_type1 = get_share_type(context, share_type_id1)
    share_type2 = get_share_type(context, share_type_id2)

    extra_specs1 = share_type1.get('extra_specs')
    extra_specs2 = share_type2.get('extra_specs')
    diff['extra_specs'], equal = _dict_diff(extra_specs1, extra_specs2)
    if not equal:
        all_equal = False

    return (diff, all_equal)


def get_extra_specs_from_share(share):
    type_id = share.get('share_type_id', None)
    return get_share_type_extra_specs(type_id)


def parse_boolean_extra_spec(extra_spec_key, extra_spec_value):
    """Parse extra spec values of the form '<is> True' or '<is> False'

    This method returns the boolean value of an extra spec value.  If
    the value does not conform to the standard boolean pattern, it raises
    an InvalidExtraSpec exception.
    """

    try:
        if not isinstance(extra_spec_value, six.string_types):
            raise ValueError

        match = re.match(r'^<is>\s*(?P<value>True|False)$',
                         extra_spec_value.strip(),
                         re.IGNORECASE)
        if not match:
            raise ValueError
        else:
            return strutils.bool_from_string(match.group('value'), strict=True)
    except ValueError:
        msg = (_('Invalid boolean extra spec %(key)s : %(value)s') %
               {'key': extra_spec_key, 'value': extra_spec_value})
        raise exception.InvalidExtraSpec(reason=msg)
