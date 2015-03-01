..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

Configure multiple back ends
============================
An administrator can configure an instance of Manila to provision shares from
one or more back ends. Each back end leverages an instance of a vendor-specific
implementation of the Manila driver API.

The name of the back end is declared as a configuration option
share_backend_name within a particular configuration stanza that contains the
related configuration options for that back end.

Administrators can specify that a particular share type be explicitly
associated with a single back end by including the extra spec
share_backend_name with the name specified within the back end configuration
stanza. When the Manila scheduler receives a provisioning request for a share
type with this extra spec set, it will fulfill the share provisioning request
on the specified back end (assuming all other scheduling criteria including
available capacity are met).

Enable multiple back ends
=========================
To enable multiple share back ends, you must set the enabled_share_backends
flag in the manila.conf file. This flag defines the names (separated by a
comma) of the configuration stanzas for the different back ends: one name is
associated to one configuration group for a back end.

The following example shows five configured back ends:

    [DEFAULT]

    enabled_share_backends=backendEMC1,backendEMC2,backendGeneric1,backendGeneric2,backendNetApp

    [backendEMC1]
    share_driver=manila.share.drivers.emc.driver.EMCShareDriver
    share_backend_name=backendEMC1
    emc_share_backend=vnx
    emc_nas_server=1.1.1.1
    emc_nas_password=password
    emc_nas_login=user
    emc_nas_server_container=server_2
    emc_nas_pool_name="Pool 1"

    [backendEMC2]
    share_driver=manila.share.drivers.emc.driver.EMCShareDriver
    share_backend_name=backendEMC2
    emc_share_backend=vnx
    emc_nas_server=1.1.1.1
    emc_nas_password=password
    emc_nas_login=user
    emc_nas_server_container=server_3
    emc_nas_pool_name="Pool 2"

    [backendGeneric1]
    share_driver=manila.share.drivers.generic.GenericShareDriver
    share_backend_name=one_name_for_two_backends
    service_instance_user=ubuntu_user
    service_instance_password=ubuntu_user_password
    service_image_name=ubuntu_image_name
    path_to_private_key=/home/foouser/.ssh/id_rsa
    path_to_public_key=/home/foouser/.ssh/id_rsa.pub

    [backendGeneric2]
    share_driver=manila.share.drivers.generic.GenericShareDriver
    share_backend_name=one_name_for_two_backends
    service_instance_user=centos_user
    service_instance_password=centos_user_password
    service_image_name=centos_image_name
    path_to_private_key=/home/baruser/.ssh/id_rsa
    path_to_public_key=/home/baruser/.ssh/id_rsa.pub

    [backendNetApp]
    share_driver = manila.share.drivers.netapp.common.NetAppDriver
    driver_handles_share_servers = True
    share_backend_name=backendNetApp
    netapp_login=user
    netapp_password=password
    netapp_server_hostname=1.1.1.1
    netapp_root_volume_aggregate=aggr01
