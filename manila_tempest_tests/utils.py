# Copyright 2015 Mirantis Inc.
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

import random
import re

import six
from tempest import config
import testtools

CONF = config.CONF


def get_microversion_as_tuple(microversion_str):
    """Transforms string-like microversion to two-value tuple of integers.

    Tuple of integers useful for microversion comparisons.
    """
    regex = r"^([1-9]\d*)\.([1-9]\d*|0)$"
    match = re.match(regex, microversion_str)
    if not match:
        raise ValueError(
            "Microversion does not fit template 'x.y' - %s" % microversion_str)
    return int(match.group(1)), int(match.group(2))


def is_microversion_gt(left, right):
    """Is microversion for left is greater than the right one."""
    return get_microversion_as_tuple(left) > get_microversion_as_tuple(right)


def is_microversion_ge(left, right):
    """Is microversion for left is greater than or equal to the right one."""
    return get_microversion_as_tuple(left) >= get_microversion_as_tuple(right)


def is_microversion_eq(left, right):
    """Is microversion for left is equal to the right one."""
    return get_microversion_as_tuple(left) == get_microversion_as_tuple(right)


def is_microversion_ne(left, right):
    """Is microversion for left is not equal to the right one."""
    return get_microversion_as_tuple(left) != get_microversion_as_tuple(right)


def is_microversion_le(left, right):
    """Is microversion for left is less than or equal to the right one."""
    return get_microversion_as_tuple(left) <= get_microversion_as_tuple(right)


def is_microversion_lt(left, right):
    """Is microversion for left is less than the right one."""
    return get_microversion_as_tuple(left) < get_microversion_as_tuple(right)


def is_microversion_supported(microversion):
    bottom = get_microversion_as_tuple(CONF.share.min_api_microversion)
    microversion = get_microversion_as_tuple(microversion)
    top = get_microversion_as_tuple(CONF.share.max_api_microversion)
    return bottom <= microversion <= top


def skip_if_microversion_not_supported(microversion):
    """Decorator for tests that are microversion-specific."""
    if not is_microversion_supported(microversion):
        reason = ("Skipped. Test requires microversion '%s'." % microversion)
        return testtools.skip(reason)
    return lambda f: f


def skip_if_microversion_lt(microversion):
    """Decorator for tests that are microversion-specific."""
    if is_microversion_lt(CONF.share.max_api_microversion, microversion):
        reason = ("Skipped. Test requires microversion greater than or "
                  "equal to '%s'." % microversion)
        return testtools.skip(reason)
    return lambda f: f


def rand_ip():
    """This uses the TEST-NET-3 range of reserved IP addresses.

    Using this range, which are reserved solely for use in
    documentation and example source code, should avoid any potential
    conflicts in real-world testing.
    """
    TEST_NET_3 = '203.0.113.'
    final_octet = six.text_type(random.randint(0, 255))
    return TEST_NET_3 + final_octet


def choose_matching_backend(share, pools, share_type):
    extra_specs = {}
    # fix extra specs with string values instead of boolean
    for k, v in share_type['extra_specs'].items():
        extra_specs[k] = (True if six.text_type(v).lower() == 'true'
                          else False if six.text_type(v).lower() == 'false'
                          else v)
    selected_pool = next(
        (x for x in pools if (x['name'] != share['host'] and all(
            y in x['capabilities'].items() for y in extra_specs.items()))),
        None)

    return selected_pool


def get_configured_extra_specs(variation=None):
    """Retrieve essential extra specs according to configuration in tempest.

    :param variation: can assume possible values: None to be as configured in
        tempest; 'opposite_driver_modes' for as configured in tempest but
        inverse driver mode; 'invalid' for inverse as configured in tempest,
        ideal for negative tests.
    :return: dict containing essential extra specs.
    """

    extra_specs = {'storage_protocol': CONF.share.capability_storage_protocol}

    if variation == 'invalid':
        extra_specs['driver_handles_share_servers'] = (
            not CONF.share.multitenancy_enabled)
        extra_specs['snapshot_support'] = (
            not CONF.share.capability_snapshot_support)

    elif variation == 'opposite_driver_modes':
        extra_specs['driver_handles_share_servers'] = (
            not CONF.share.multitenancy_enabled)
        extra_specs['snapshot_support'] = (
            CONF.share.capability_snapshot_support)

    else:
        extra_specs['driver_handles_share_servers'] = (
            CONF.share.multitenancy_enabled)
        extra_specs['snapshot_support'] = (
            CONF.share.capability_snapshot_support)

    return extra_specs
