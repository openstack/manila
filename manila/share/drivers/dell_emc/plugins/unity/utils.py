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
