# Copyright (c) 2014 Openstack Foundation.
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

"""Built-in volume type properties."""


from oslo.config import cfg
from oslo.db import exception as db_exception
import six

from manila import context
from manila import db
from manila import exception
from manila.i18n import _
from manila.openstack.common import log as logging

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


def create(context, name, extra_specs={}):
    """Creates volume types."""
    try:
        type_ref = db.volume_type_create(context,
                                         dict(name=name,
                                              extra_specs=extra_specs))
    except db_exception.DBError as e:
        LOG.exception(_('DB error: %s'), e)
        raise exception.VolumeTypeCreateFailed(name=name,
                                               extra_specs=extra_specs)
    return type_ref


def destroy(context, id):
    """Marks volume types as deleted."""
    if id is None:
        msg = _("id cannot be None")
        raise exception.InvalidVolumeType(reason=msg)
    else:
        db.volume_type_destroy(context, id)


def get_all_types(context, inactive=0, search_opts={}):
    """Get all non-deleted volume_types.

    Pass true as argument if you want deleted volume types returned also.
    """
    vol_types = db.volume_type_get_all(context, inactive)

    if search_opts:
        LOG.debug("Searching by: %s", search_opts)

        def _check_extra_specs_match(vol_type, searchdict):
            for k, v in six.iteritems(searchdict):
                if (k not in vol_type['extra_specs'].keys()
                        or vol_type['extra_specs'][k] != v):
                    return False
            return True

        # search_option to filter_name mapping.
        filter_mapping = {'extra_specs': _check_extra_specs_match}

        result = {}
        for type_name, type_args in six.iteritems(vol_types):
            # go over all filters in the list
            for opt, values in six.iteritems(search_opts):
                try:
                    filter_func = filter_mapping[opt]
                except KeyError:
                    # no such filter - ignore it, go to next filter
                    continue
                else:
                    if filter_func(type_args, values):
                        result[type_name] = type_args
                        break
        vol_types = result
    return vol_types


def get_volume_type(ctxt, id):
    """Retrieves single volume type by id."""
    if id is None:
        msg = _("id cannot be None")
        raise exception.InvalidVolumeType(reason=msg)

    if ctxt is None:
        ctxt = context.get_admin_context()

    return db.volume_type_get(ctxt, id)


def get_volume_type_by_name(context, name):
    """Retrieves single volume type by name."""
    if name is None:
        msg = _("name cannot be None")
        raise exception.InvalidVolumeType(reason=msg)

    return db.volume_type_get_by_name(context, name)


def get_default_volume_type():
    """Get the default volume type."""
    name = CONF.default_volume_type
    vol_type = {}

    if name is not None:
        ctxt = context.get_admin_context()
        try:
            vol_type = get_volume_type_by_name(ctxt, name)
        except exception.VolumeTypeNotFoundByName as e:
            # Couldn't find volume type with the name in default_volume_type
            # flag, record this issue and move on
            # TODO(zhiteng) consider add notification to warn admin
            LOG.exception(_('Default volume type is not found, '
                            'please check default_volume_type config: %s'), e)

    return vol_type


def get_volume_type_extra_specs(volume_type_id, key=False):
    volume_type = get_volume_type(context.get_admin_context(),
                                  volume_type_id)
    extra_specs = volume_type['extra_specs']
    if key:
        if extra_specs.get(key):
            return extra_specs.get(key)
        else:
            return False
    else:
        return extra_specs


def volume_types_diff(context, vol_type_id1, vol_type_id2):
    """Returns a 'diff' of two volume types and whether they are equal.

    Returns a tuple of (diff, equal), where 'equal' is a boolean indicating
    whether there is any difference, and 'diff' is a dictionary with the
    following format:
    {'extra_specs': {'key1': (value_in_1st_vol_type, value_in_2nd_vol_type),
    'key2': (value_in_1st_vol_type, value_in_2nd_vol_type),
    ...}
    """

    def _dict_diff(dict1, dict2):
        res = {}
        equal = True
        if dict1 is None:
            dict1 = {}
        if dict2 is None:
            dict2 = {}
        for k, v in six.iteritems(dict1):
            res[k] = (v, dict2.get(k))
            if k not in dict2 or res[k][0] != res[k][1]:
                equal = False
        for k, v in six.iteritems(dict2):
            res[k] = (dict1.get(k), v)
            if k not in dict1 or res[k][0] != res[k][1]:
                equal = False
        return (res, equal)

    all_equal = True
    diff = {}
    vol_type1 = get_volume_type(context, vol_type_id1)
    vol_type2 = get_volume_type(context, vol_type_id2)

    extra_specs1 = vol_type1.get('extra_specs')
    extra_specs2 = vol_type2.get('extra_specs')
    diff['extra_specs'], equal = _dict_diff(extra_specs1, extra_specs2)
    if not equal:
        all_equal = False

    return (diff, all_equal)
