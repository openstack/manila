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
from tempest.common import credentials_factory as common_creds

from manila_tempest_tests.services.share.json import shares_client
from manila_tempest_tests.services.share.v2.json import shares_client \
    as shares_v2_client


class Manager(clients.Manager):
    def __init__(
            self,
            credentials=common_creds.get_configured_credentials('user'),
            service=None):
        super(Manager, self).__init__(credentials, service)
        self.shares_client = shares_client.SharesClient(self.auth_provider)
        self.shares_v2_client = shares_v2_client.SharesV2Client(
            self.auth_provider)


class AltManager(Manager):
    def __init__(self, service=None):
        super(AltManager, self).__init__(
            common_creds.get_configured_credentials('alt_user'), service)


class AdminManager(Manager):
    def __init__(self, service=None):
        super(AdminManager, self).__init__(
            common_creds.get_configured_credentials('identity_admin'),
            service)
