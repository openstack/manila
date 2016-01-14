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


@six.add_metaclass(abc.ABCMeta)
class NetAppBaseHelper(object):
    """Interface for protocol-specific NAS drivers."""

    def __init__(self):
        self._client = None

    def set_client(self, client):
        self._client = client

    @abc.abstractmethod
    def create_share(self, share, share_name, export_addresses):
        """Creates NAS share."""

    @abc.abstractmethod
    def delete_share(self, share, share_name):
        """Deletes NAS share."""

    @abc.abstractmethod
    def allow_access(self, context, share, share_name, access):
        """Allows new_rules to a given NAS storage in new_rules."""

    @abc.abstractmethod
    def deny_access(self, context, share, share_name, access):
        """Denies new_rules to a given NAS storage in new_rules."""

    @abc.abstractmethod
    def get_target(self, share):
        """Returns host where the share located."""

    @abc.abstractmethod
    def get_share_name_for_share(self, share):
        """Returns the flexvol name that hosts a share."""
