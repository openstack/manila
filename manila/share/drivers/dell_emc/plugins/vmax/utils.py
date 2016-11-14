# Copyright (c) 2016 Dell Inc. or its subsidiaries.
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

import types

from oslo_config import cfg
from oslo_log import log
from oslo_utils import fnmatch
from oslo_utils import timeutils

CONF = cfg.CONF
LOG = log.getLogger(__name__)


def decorate_all_methods(decorator, debug_only=False):
    if debug_only and not CONF.debug:
        return lambda cls: cls

    def _decorate_all_methods(cls):
        for attr_name, attr_val in cls.__dict__.items():
            if (isinstance(attr_val, types.FunctionType) and
                    not attr_name.startswith("_")):
                setattr(cls, attr_name, decorator(attr_val))
        return cls

    return _decorate_all_methods


def log_enter_exit(func):
    if not CONF.debug:
        return func

    def inner(self, *args, **kwargs):
        LOG.debug("Entering %(cls)s.%(method)s.",
                  {'cls': self.__class__.__name__,
                   'method': func.__name__})
        start = timeutils.utcnow()
        ret = func(self, *args, **kwargs)
        end = timeutils.utcnow()
        LOG.debug("Exiting %(cls)s.%(method)s. "
                  "Spent %(duration)s sec. "
                  "Return %(return)s.",
                  {'cls': self.__class__.__name__,
                   'duration': timeutils.delta_seconds(start, end),
                   'method': func.__name__,
                   'return': ret})
        return ret

    return inner


def do_match_any(full, matcher_list):
    """Finds items that match any of the matchers.

    :param full: Full item list
    :param matcher_list: The list of matchers. Each matcher supports
                         Unix shell-style wildcards
    :return: The matched items set and the unmatched items set
    """
    matched = set()
    not_matched = set()

    full = set([item.strip() for item in full])
    matcher_list = set([item.strip() for item in matcher_list])

    for matcher in matcher_list:
        for item in full:
            if fnmatch.fnmatchcase(item, matcher):
                matched.add(item)
    not_matched = full - matched
    return matched, not_matched
