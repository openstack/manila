# Copyright (c) 2016 EMC Corporation.
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
""" Utility module for EMC Unity Manila Driver """

from oslo_utils import fnmatch
from oslo_utils import units

from manila import exception
from manila.i18n import _


def do_match(full, matcher_list):
    matched = set()

    full = set([item.strip() for item in full])
    if matcher_list is None:
        # default to all
        matcher_list = set('*')
    else:
        matcher_list = set([item.strip() for item in matcher_list])

    for item in full:
        for matcher in matcher_list:
            if fnmatch.fnmatchcase(item, matcher):
                matched.add(item)
    return matched, full - matched


def match_ports(ports_list, port_ids_conf):
    """Filters the port in `ports_list` with the port id in `port_ids_conf`.

    A tuple of (`sp_ports_map`, `unmanaged_port_ids`) is returned, in which
    `sp_ports_map` is a dict whose key is SPA or SPB, value is the matched port
    id set, `unmanaged_port_ids` is the un-matched port id set.
    """
    patterns = (set('*') if port_ids_conf is None
                else set(item.strip() for item in port_ids_conf
                         if item.strip()))
    if not patterns:
        patterns = set('*')

    sp_ports_map = {}
    unmanaged_port_ids = set()
    for port in ports_list:
        port_id = port.get_id()
        for pattern in patterns:
            if fnmatch.fnmatchcase(port_id, pattern):
                sp_id = port.parent_storage_processor.get_id()
                ports_set = sp_ports_map.setdefault(sp_id, set())
                ports_set.add(port_id)
                break
        else:
            unmanaged_port_ids.add(port_id)
    return sp_ports_map, unmanaged_port_ids


def find_ports_by_mtu(all_ports, port_ids_conf, mtu):
    valid_ports = list(filter(lambda p: p.mtu == mtu, all_ports))
    managed_port_map, unmatched = match_ports(valid_ports, port_ids_conf)
    if not managed_port_map:
        msg = (_('None of the configured port %(conf)s matches the mtu '
                 '%{mtu}s.') % {'conf': port_ids_conf, 'mtu': mtu})
        raise exception.ShareBackendException(msg=msg)
    return managed_port_map


def gib_to_byte(size_gib):
    return size_gib * units.Gi
