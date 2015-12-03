# Copyright (c) 2011 OpenStack Foundation.
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
Scheduler host weighers
"""

from manila.scheduler.weighers import base


class WeighedHost(base.WeighedObject):
    def to_dict(self):
        return {
            'weight': self.weight,
            'host': self.obj.host,
        }

    def __repr__(self):
        return ("WeighedHost [host: %s, weight: %s]" %
                (self.obj.host, self.weight))


class BaseHostWeigher(base.BaseWeigher):
    """Base class for host weighers."""
    pass


class HostWeightHandler(base.BaseWeightHandler):
    object_class = WeighedHost

    def __init__(self, namespace):
        super(HostWeightHandler, self).__init__(BaseHostWeigher, namespace)
