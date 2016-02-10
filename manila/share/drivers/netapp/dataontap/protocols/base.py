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
"""
Abstract base class for NetApp NAS protocol helper classes.
"""

import abc

import six

from manila.common import constants
from manila import utils


def access_rules_synchronized(f):
    """Decorator for synchronizing share access rule modification methods."""

    def wrapped_func(self, *args, **kwargs):

        # The first argument is always a share, which has an ID
        key = "share-access-%s" % args[0]['id']

        @utils.synchronized(key)
        def source_func(self, *args, **kwargs):
            return f(self, *args, **kwargs)

        return source_func(self, *args, **kwargs)

    return wrapped_func


@six.add_metaclass(abc.ABCMeta)
class NetAppBaseHelper(object):
    """Interface for protocol-specific NAS drivers."""

    def __init__(self):
        self._client = None

    def set_client(self, client):
        self._client = client

    def _is_readonly(self, access_level):
        """Returns whether an access rule specifies read-only access."""
        return access_level == constants.ACCESS_LEVEL_RO

    @abc.abstractmethod
    def create_share(self, share, share_name):
        """Creates NAS share."""

    @abc.abstractmethod
    def delete_share(self, share, share_name):
        """Deletes NAS share."""

    @abc.abstractmethod
    def update_access(self, share, share_name, rules):
        """Replaces the list of access rules known to the backend storage."""

    @abc.abstractmethod
    def get_target(self, share):
        """Returns host where the share located."""

    @abc.abstractmethod
    def get_share_name_for_share(self, share):
        """Returns the flexvol name that hosts a share."""
