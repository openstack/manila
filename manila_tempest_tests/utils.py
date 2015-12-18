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


def rand_ip():
    """This uses the TEST-NET-3 range of reserved IP addresses.

    Using this range, which are reserved solely for use in
    documentation and example source code, should avoid any potential
    conflicts in real-world testing.
    """
    TEST_NET_3 = '203.0.113.'
    final_octet = six.text_type(random.randint(0, 255))
    return TEST_NET_3 + final_octet
