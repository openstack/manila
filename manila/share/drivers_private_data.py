# Copyright 2015 Mirantis inc.
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
"""
Module provides possibility for share drivers to store private information
related to common Manila models like Share or Snapshot.

"""

import abc

from oslo_config import cfg
from oslo_utils import importutils
from oslo_utils import uuidutils
import six

from manila.db import api as db_api
from manila.i18n import _

private_data_opts = [
    cfg.StrOpt(
        'drivers_private_storage_class',
        default='manila.share.drivers_private_data.SqlStorageDriver',
        help='The full class name of the Private Data Driver class to use.'),
]

CONF = cfg.CONF


@six.add_metaclass(abc.ABCMeta)
class StorageDriver(object):

    def __init__(self, context, backend_host):
        # Backend shouldn't access data stored by another backend
        self.backend_host = backend_host
        self.context = context

    @abc.abstractmethod
    def get(self, entity_id, key, default):
        """Backend implementation for DriverPrivateData.get() method.

           Should return all keys for given 'entity_id' if 'key' is None.
           Otherwise should return value for provided 'key'.
           If values for provided 'entity_id' or 'key' not found,
           should return 'default'.

           See DriverPrivateData.get() method for more details.
        """

    @abc.abstractmethod
    def update(self, entity_id, details, delete_existing):
        """Backend implementation for DriverPrivateData.update() method.

           Should update details for given 'entity_id' with behaviour defined
           by 'delete_existing' boolean flag.

           See DriverPrivateData.update() method for more details.
        """

    @abc.abstractmethod
    def delete(self, entity_id, key):
        """Backend implementation for DriverPrivateData.delete() method.

           Should return delete all keys if 'key' is None.
           Otherwise should delete value for provided 'key'.

           See DriverPrivateData.update() method for more details.
        """


class SqlStorageDriver(StorageDriver):

    def update(self, entity_id, details, delete_existing):
        return db_api.driver_private_data_update(
            self.context, entity_id, details,
            delete_existing
        )

    def get(self, entity_id, key, default):
        return db_api.driver_private_data_get(
            self.context, entity_id, key, default
        )

    def delete(self, entity_id, key):
        return db_api.driver_private_data_delete(
            self.context, entity_id, key
        )


class DriverPrivateData(object):
    def __init__(self, storage=None, *args, **kwargs):
        """Init method.

        :param storage: None or inheritor of StorageDriver abstract class
        :param config_group: Optional -- Config group used for loading settings
        :param context: Optional -- Current context
        :param backend_host: Optional -- Driver host
        """

        config_group_name = kwargs.get('config_group')
        CONF.register_opts(private_data_opts, group=config_group_name)

        if storage is not None:
            self._storage = storage
        elif 'context' in kwargs and 'backend_host' in kwargs:
            if config_group_name:
                conf = getattr(CONF, config_group_name)
            else:
                conf = CONF
            storage_class = conf.drivers_private_storage_class
            cls = importutils.import_class(storage_class)
            self._storage = cls(kwargs.get('context'),
                                kwargs.get('backend_host'))
        else:
            msg = _("You should provide 'storage' parameter or"
                    " 'context' and 'backend_host' parameters.")
            raise ValueError(msg)

    def get(self, entity_id, key=None, default=None):
        """Get one, list or all key-value pairs.

        :param entity_id: Model UUID
        :param key: Key string or list of keys
        :param default: Default value for case when key(s) not found
        :returns: string or dict
        """
        self._validate_entity_id(entity_id)
        return self._storage.get(entity_id, key, default)

    def update(self, entity_id, details, delete_existing=False):
        """Update or create specified key-value pairs.

        :param entity_id: Model UUID
        :param details: dict with key-value pairs data. Keys and values should
                        be strings.
        :param delete_existing: boolean flag which determines behaviour
                                for existing key-value pairs:
                                True - remove all existing key-value pairs
                                False (default) - leave as is
        """
        self._validate_entity_id(entity_id)

        if not isinstance(details, dict):
            msg = (_("Provided details %s is not valid dict.")
                   % six.text_type(details))
            raise ValueError(msg)

        return self._storage.update(
            entity_id, details, delete_existing)

    def delete(self, entity_id, key=None):
        """Delete one, list or all key-value pairs.

        :param entity_id: Model UUID
        :param key: Key string or list of keys
        """
        self._validate_entity_id(entity_id)
        return self._storage.delete(entity_id, key)

    @staticmethod
    def _validate_entity_id(entity_id):
        if not uuidutils.is_uuid_like(entity_id):
            msg = (_("Provided entity_id %s is not valid UUID.")
                   % six.text_type(entity_id))
            raise ValueError(msg)
