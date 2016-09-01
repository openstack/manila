# Copyright 2016 Nexenta Systems, Inc.
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

import re
import six

from oslo_utils import units


def str2size(s, scale=1024):
    """Convert size-string.

    String format: <value>[:space:]<B | K | M | ...> to bytes.

    :param s: size-string
    :param scale: base size
    """
    if not s:
        return 0
    if isinstance(s, six.integer_types):
        return s

    match = re.match(r'^([\.\d]+)\s*([BbKkMmGgTtPpEeZzYy]?)', s)
    if match is None:
        raise ValueError('Invalid value: %s' % s)
    groups = match.groups()
    value = float(groups[0])
    suffix = len(groups) > 1 and groups[1].upper() or 'B'
    types = ('B', 'K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y')
    for i, t in enumerate(types):
        if suffix == t:
            return float(value * pow(scale, i))


def str2gib_size(s):
    """Covert size-string to size in gigabytes."""
    size_in_bytes = str2size(s)
    return size_in_bytes // units.Gi


def bytes_to_gb(size):
    return float(size) / units.Gi
