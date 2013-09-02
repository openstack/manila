#    Copyright 2012 OpenStack LLC
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

from manila import context
from manila import flags
from manila.openstack.common import importutils
from manila import test
from manila.volume.drivers.solidfire import SolidFire

FLAGS = flags.FLAGS

RBD_MODULE = "manila.volume.drivers.rbd.RBDDriver"
SHEEPDOG_MODULE = "manila.volume.drivers.sheepdog.SheepdogDriver"
NEXENTA_MODULE = "manila.volume.drivers.nexenta.volume.NexentaDriver"
SAN_MODULE = "manila.volume.drivers.san.san.SanISCSIDriver"
SOLARIS_MODULE = "manila.volume.drivers.san.solaris.SolarisISCSIDriver"
LEFTHAND_MODULE = "manila.volume.drivers.san.hp_lefthand.HpSanISCSIDriver"
NETAPP_MODULE = "manila.volume.drivers.netapp.iscsi.NetAppISCSIDriver"
NETAPP_CMODE_MODULE =\
    "manila.volume.drivers.netapp.iscsi.NetAppCmodeISCSIDriver"
NETAPP_NFS_MODULE = "manila.volume.drivers.netapp.nfs.NetAppNFSDriver"
NFS_MODULE = "manila.volume.drivers.nfs.NfsDriver"
SOLIDFIRE_MODULE = "manila.volume.drivers.solidfire.SolidFire"
STORWIZE_SVC_MODULE = "manila.volume.drivers.storwize_svc.StorwizeSVCDriver"
WINDOWS_MODULE = "manila.volume.drivers.windows.WindowsDriver"
XIV_MODULE = "manila.volume.drivers.xiv.XIVDriver"
ZADARA_MODULE = "manila.volume.drivers.zadara.ZadaraVPSAISCSIDriver"


class VolumeDriverCompatibility(test.TestCase):
    """Test backwards compatibility for volume drivers."""

    def fake_update_cluster_status(self):
        return

    def setUp(self):
        super(VolumeDriverCompatibility, self).setUp()
        self.manager = importutils.import_object(FLAGS.volume_manager)
        self.context = context.get_admin_context()

    def tearDown(self):
        super(VolumeDriverCompatibility, self).tearDown()

    def _load_driver(self, driver):
        if 'SolidFire' in driver:
            # SolidFire driver does update_cluster stat on init
            self.stubs.Set(SolidFire, '_update_cluster_status',
                           self.fake_update_cluster_status)
        self.manager.__init__(volume_driver=driver)

    def _driver_module_name(self):
        return "%s.%s" % (self.manager.driver.__class__.__module__,
                          self.manager.driver.__class__.__name__)

    def test_rbd_old(self):
        self._load_driver('manila.volume.driver.RBDDriver')
        self.assertEquals(self._driver_module_name(), RBD_MODULE)

    def test_rbd_new(self):
        self._load_driver(RBD_MODULE)
        self.assertEquals(self._driver_module_name(), RBD_MODULE)

    def test_sheepdog_old(self):
        self._load_driver('manila.volume.driver.SheepdogDriver')
        self.assertEquals(self._driver_module_name(), SHEEPDOG_MODULE)

    def test_sheepdog_new(self):
        self._load_driver(SHEEPDOG_MODULE)
        self.assertEquals(self._driver_module_name(), SHEEPDOG_MODULE)

    def test_nexenta_old(self):
        self._load_driver('manila.volume.nexenta.volume.NexentaDriver')
        self.assertEquals(self._driver_module_name(), NEXENTA_MODULE)

    def test_nexenta_new(self):
        self._load_driver(NEXENTA_MODULE)
        self.assertEquals(self._driver_module_name(), NEXENTA_MODULE)

    def test_san_old(self):
        self._load_driver('manila.volume.san.SanISCSIDriver')
        self.assertEquals(self._driver_module_name(), SAN_MODULE)

    def test_san_new(self):
        self._load_driver(SAN_MODULE)
        self.assertEquals(self._driver_module_name(), SAN_MODULE)

    def test_solaris_old(self):
        self._load_driver('manila.volume.san.SolarisISCSIDriver')
        self.assertEquals(self._driver_module_name(), SOLARIS_MODULE)

    def test_solaris_new(self):
        self._load_driver(SOLARIS_MODULE)
        self.assertEquals(self._driver_module_name(), SOLARIS_MODULE)

    def test_hp_lefthand_old(self):
        self._load_driver('manila.volume.san.HpSanISCSIDriver')
        self.assertEquals(self._driver_module_name(), LEFTHAND_MODULE)

    def test_hp_lefthand_new(self):
        self._load_driver(LEFTHAND_MODULE)
        self.assertEquals(self._driver_module_name(), LEFTHAND_MODULE)

    def test_netapp_old(self):
        self._load_driver('manila.volume.netapp.NetAppISCSIDriver')
        self.assertEquals(self._driver_module_name(), NETAPP_MODULE)

    def test_netapp_new(self):
        self._load_driver(NETAPP_MODULE)
        self.assertEquals(self._driver_module_name(), NETAPP_MODULE)

    def test_netapp_cmode_old(self):
        self._load_driver('manila.volume.netapp.NetAppCmodeISCSIDriver')
        self.assertEquals(self._driver_module_name(), NETAPP_CMODE_MODULE)

    def test_netapp_cmode_new(self):
        self._load_driver(NETAPP_CMODE_MODULE)
        self.assertEquals(self._driver_module_name(), NETAPP_CMODE_MODULE)

    def test_netapp_nfs_old(self):
        self._load_driver('manila.volume.netapp_nfs.NetAppNFSDriver')
        self.assertEquals(self._driver_module_name(), NETAPP_NFS_MODULE)

    def test_netapp_nfs_new(self):
        self._load_driver(NETAPP_NFS_MODULE)
        self.assertEquals(self._driver_module_name(), NETAPP_NFS_MODULE)

    def test_nfs_old(self):
        self._load_driver('manila.volume.nfs.NfsDriver')
        self.assertEquals(self._driver_module_name(), NFS_MODULE)

    def test_nfs_new(self):
        self._load_driver(NFS_MODULE)
        self.assertEquals(self._driver_module_name(), NFS_MODULE)

    def test_solidfire_old(self):
        self._load_driver('manila.volume.solidfire.SolidFire')
        self.assertEquals(self._driver_module_name(), SOLIDFIRE_MODULE)

    def test_solidfire_new(self):
        self._load_driver(SOLIDFIRE_MODULE)
        self.assertEquals(self._driver_module_name(), SOLIDFIRE_MODULE)

    def test_storwize_svc_old(self):
        self._load_driver('manila.volume.storwize_svc.StorwizeSVCDriver')
        self.assertEquals(self._driver_module_name(), STORWIZE_SVC_MODULE)

    def test_storwize_svc_new(self):
        self._load_driver(STORWIZE_SVC_MODULE)
        self.assertEquals(self._driver_module_name(), STORWIZE_SVC_MODULE)

    def test_windows_old(self):
        self._load_driver('manila.volume.windows.WindowsDriver')
        self.assertEquals(self._driver_module_name(), WINDOWS_MODULE)

    def test_windows_new(self):
        self._load_driver(WINDOWS_MODULE)
        self.assertEquals(self._driver_module_name(), WINDOWS_MODULE)

    def test_xiv_old(self):
        self._load_driver('manila.volume.xiv.XIVDriver')
        self.assertEquals(self._driver_module_name(), XIV_MODULE)

    def test_xiv_new(self):
        self._load_driver(XIV_MODULE)
        self.assertEquals(self._driver_module_name(), XIV_MODULE)

    def test_zadara_old(self):
        self._load_driver('manila.volume.zadara.ZadaraVPSAISCSIDriver')
        self.assertEquals(self._driver_module_name(), ZADARA_MODULE)

    def test_zadara_new(self):
        self._load_driver(ZADARA_MODULE)
        self.assertEquals(self._driver_module_name(), ZADARA_MODULE)
