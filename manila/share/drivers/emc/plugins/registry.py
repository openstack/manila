# Copyright (c) 2014 EMC Corporation.
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

"""EMC Share Driver Plugin Framework."""

g_registered_storage_backends = {}


def register_storage_backend(share_backend_name, storage_conn_class):
    """register a backend storage plugins."""
    g_registered_storage_backends[
        share_backend_name.upper()] = storage_conn_class


def create_storage_connection(share_backend_name, logger):
    """create an instance of plugins."""
    storage_conn_class = g_registered_storage_backends[
        share_backend_name.upper()]
    return storage_conn_class(logger)
