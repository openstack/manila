# Copyright (c) 2014, Oracle and/or its affiliates. All rights reserved.
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
Fake ZFS Storage Appliance, for unit testing.
"""


class FakeResponse(object):
    def __init__(self, statuscode):
        self.status = statuscode
        self.data = 'data'


class FakeZFSSA(object):
    """Fake ZFS SA."""
    def __init__(self):
        self.user = None
        self.host = 'fakehost'
        self.url = 'fakeurl'
        self.rclient = None

    def login(self, user):
        self.user = user

    def set_host(self, host, timeout=None):
        self.host = host

    def enable_service(self, service):
        return True

    def create_project(self, pool, project, arg):
        pass

    def get_share(self, pool, project, share):
        pass

    def create_share(self, pool, project, share):
        pass

    def delete_share(self, pool, project, share):
        pass

    def create_snapshot(self, pool, project, share):
        pass

    def delete_snapshot(self, pool, project, share, snapshot):
        pass

    def clone_snapshot(self, pool, project, share, snapshot, clone, size):
        pass

    def has_clones(self, pool, project, vol, snapshot):
        return False

    def modify_share(self, pool, project, share, arg):
        pass

    def allow_access_nfs(self, pool, project, share, access):
        pass

    def deny_access_nfs(self, pool, project, share, access):
        pass

    def get_project_stats(self, pool, project):
        pass

    def create_schema(self, schema):
        pass


class FakeRestClient(object):
    """Fake ZFSSA Rest Client."""
    def __init__(self):
        self.url = None
        self.headers = None
        self.log_function = None
        self.local = None
        self.base_path = None
        self.timeout = 60
        self.do_logout = False
        self.auth_str = None

    def _path(self, path, base_path=None):
        pass

    def _authoriza(self):
        pass

    def login(self, auth_str):
        pass

    def logout(self):
        pass

    def islogin(self):
        pass

    def request(self, path, request, body=None, **kwargs):
        pass

    def get(self, path, **kwargs):
        pass

    def post(self, path, body="", **kwargs):
        pass

    def put(self, path, body="", **kwargs):
        pass

    def delete(self, path, **kwargs):
        pass

    def head(self, path, **kwargs):
        pass
