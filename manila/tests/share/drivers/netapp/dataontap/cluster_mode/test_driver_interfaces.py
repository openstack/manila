# Copyright (c) 2015 Clinton Knight.  All rights reserved.
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
Mock unit tests for the NetApp file share driver interfaces
"""


import mock
import six

from manila.share.drivers.netapp.dataontap.cluster_mode import drv_multi_svm
from manila.share.drivers.netapp.dataontap.cluster_mode import drv_single_svm
from manila import test


class NetAppFileStorageDriverInterfaceTestCase(test.TestCase):

    def setUp(self):
        super(NetAppFileStorageDriverInterfaceTestCase, self).setUp()

        self.mock_object(drv_multi_svm.NetAppCmodeMultiSvmShareDriver,
                         '__init__',
                         mock.Mock(return_value=None))
        self.mock_object(drv_single_svm.NetAppCmodeSingleSvmShareDriver,
                         '__init__',
                         mock.Mock(return_value=None))

        self.drv_multi_svm = drv_multi_svm.NetAppCmodeMultiSvmShareDriver()
        self.drv_single_svm = drv_single_svm.NetAppCmodeSingleSvmShareDriver()

    def test_driver_interfaces_match(self):
        """Ensure the NetApp file storage driver interfaces match.

        The two file share Manila drivers from NetApp (cDOT multi-SVM,
        cDOT single-SVM) are merely passthrough shim layers atop a common
        file storage library.  Bugs are easily introduced when a Manila
        method is exposed via a subset of those driver shims.  This test
        ensures they remain in sync and the library features are uniformly
        available in the drivers.
        """

        # Get local functions of each driver interface
        multi_svm_methods = self._get_local_functions(self.drv_multi_svm)
        single_svm_methods = self._get_local_functions(self.drv_single_svm)

        # Ensure NetApp file share driver shims are identical
        self.assertSetEqual(multi_svm_methods, single_svm_methods)

    def _get_local_functions(self, obj):
        """Get function names of an object without superclass functions."""
        return set([key for key, value in six.iteritems(type(obj).__dict__)
                    if callable(value)])
