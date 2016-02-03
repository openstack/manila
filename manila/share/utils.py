# Copyright (c) 2012 OpenStack Foundation
# Copyright (c) 2015 Rushil Chugh
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

"""Share-related Utilities and helpers."""

from oslo_log import log

LOG = log.getLogger(__name__)

DEFAULT_POOL_NAME = '_pool0'


def extract_host(host, level='backend', use_default_pool_name=False):
    """Extract Host, Backend or Pool information from host string.

    :param host: String for host, which could include host@backend#pool info
    :param level: Indicate which level of information should be extracted
                  from host string. Level can be 'host', 'backend', 'pool',
                  or 'backend_name', default value is 'backend'
    :param use_default_pool_name: This flag specifies what to do
                              if level == 'pool' and there is no 'pool' info
                              encoded in host string.  default_pool_name=True
                              will return DEFAULT_POOL_NAME, otherwise it will
                              return None. Default value of this parameter
                              is False.
    :return: expected level of information

    For example:
        host = 'HostA@BackendB#PoolC'
        ret = extract_host(host, 'host')
        # ret is 'HostA'
        ret = extract_host(host, 'backend')
        # ret is 'HostA@BackendB'
        ret = extract_host(host, 'pool')
        # ret is 'PoolC'
        ret = extract_host(host, 'backend_name')
        # ret is 'BackendB'
        host = 'HostX@BackendY'
        ret = extract_host(host, 'pool')
        # ret is None
        ret = extract_host(host, 'pool', True)
        # ret is '_pool0'
    """
    if level == 'host':
        # Make sure pool is not included
        hst = host.split('#')[0]
        return hst.split('@')[0]
    if level == 'backend_name':
        hst = host.split('#')[0]
        return hst.split('@')[1]
    elif level == 'backend':
        return host.split('#')[0]
    elif level == 'pool':
        lst = host.split('#')
        if len(lst) == 2:
            return lst[1]
        elif use_default_pool_name is True:
            return DEFAULT_POOL_NAME
        else:
            return None


def append_host(host, pool):
    """Encode pool into host info."""
    if not host or not pool:
        return host

    new_host = "#".join([host, pool])
    return new_host
