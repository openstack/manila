# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
from tempest import config_shares as config
from tempest import exceptions
from tempest.services.shares.json import shares_client as j_shares_client
from tempest.services.shares.xml import shares_client as x_shares_client

CONF = config.CONF


class Manager(clients.Manager):

    """
    Top level manager for OpenStack Compute clients
    """

    def __init__(self, username=None, password=None, tenant_name=None,
                 interface='json'):
        super(Manager, self).__init__(username, password, tenant_name,
                                      interface)

        client_args = (CONF, self.username, self.password,
                       self.auth_url, self.tenant_name)
        if interface == 'xml':
            self.shares_client = x_shares_client.SharesClientXML(*client_args)
        elif interface == 'json':
            self.shares_client = j_shares_client.SharesClientJSON(*client_args)
        else:
            msg = "Unsupported interface type `%s'" % interface
            raise exceptions.InvalidConfiguration(msg)


class AltManager(Manager):

    """
    Manager object that uses the alt_XXX credentials for its
    managed client objects
    """

    def __init__(self, interface='json'):
        super(AltManager, self).__init__(CONF.identity.alt_username,
                                         CONF.identity.alt_password,
                                         CONF.identity.alt_tenant_name,
                                         interface=interface)


class AdminManager(Manager):

    """
    Manager object that uses the admin credentials for its
    managed client objects
    """

    def __init__(self, interface='json'):
        super(AdminManager, self).__init__(CONF.identity.admin_username,
                                           CONF.identity.admin_password,
                                           CONF.identity.admin_tenant_name,
                                           interface=interface)
