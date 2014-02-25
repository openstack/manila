# Copyright 2014 Mirantis Inc.
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

from tempest import clients
from tempest import config_share as config
from tempest.services.share.json import shares_client


CONF = config.CONF


class Manager(clients.Manager):

    """
    Top level manager for OpenStack Compute clients
    """

    def __init__(self, username=None, password=None, tenant_name=None,
                 interface='json', service=None):
        super(Manager, self).__init__(username, password, tenant_name,
                                      interface, service)
        auth_provider = self.get_auth_provider(self.credentials)
        if interface == 'json':
            self.shares_client = shares_client.SharesClient(auth_provider)


class AltManager(Manager):
    def __init__(self, interface='json'):
        super(AltManager, self).__init__(CONF.identity.alt_username,
                                         CONF.identity.alt_password,
                                         CONF.identity.alt_tenant_name,
                                         interface=interface)


class AdminManager(Manager):
    def __init__(self, interface='json'):
        super(AdminManager, self).__init__(CONF.identity.admin_username,
                                           CONF.identity.admin_password,
                                           CONF.identity.admin_tenant_name,
                                           interface=interface)
