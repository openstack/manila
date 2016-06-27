# Copyright (c) 2016 Hewlett-Packard Enterprise Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

from tempest import config
from tempest.lib.services import clients


CONF = config.CONF


class Clients(clients.ServiceClients):
    """Tempest stable service clients and loaded plugins service clients"""

    def __init__(self, credentials, service=None):
        """Emulate the interface of Tempest's clients.Manager"""
        # Identity settings
        if CONF.identity.auth_version == 'v2':
            identity_uri = CONF.identity.uri
        else:
            identity_uri = CONF.identity.uri_v3
        super(Clients, self).__init__(credentials, identity_uri)
