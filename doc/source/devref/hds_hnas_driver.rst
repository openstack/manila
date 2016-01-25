..
      Copyright 2015 Hitachi Data Systems, Inc.
      All Rights Reserved.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

           http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

==========================
Hitachi HNAS manila driver
==========================
------------------
Driver Version 1.0
------------------

This OpenStack manila driver provides support for Hitachi Data Systems (HDS)
NAS Platform Models 3080, 3090, 4040, 4060, 4080 and 4100.

HNAS Storage Requirements
'''''''''''''''''''''''''

Before using Hitachi HNAS manila driver, use the HNAS configuration and
management utilities, such as GUI (SMU) or SSC CLI to create a storage pool
(span) and an EVS. Also, check that HNAS/SMU software version is
12.2 or higher.

Supported Operations
''''''''''''''''''''

The following operations are supported in this version of manila HNAS driver:
 - Create and delete NFS shares;
 - Extend NFS shares;
 - Manage rules to NFS shares (allow/deny access);
 - Manage and unmanage NFS shares;
 - Create and delete snapshots;
 - Create shares from snapshots.

Driver Configuration
''''''''''''''''''''

To configure the driver, make sure that the controller and compute nodes have
access to the HNAS management port, and compute and neutron nodes have
access to the data ports (EVS IPs or aggregations). If manila-share service
is not running on controller node, it must have access to the management port.
The driver configuration can be summarized in the following steps:

| 1) Create a file system to be used by manila on HNAS. Make sure that the
 filesystem is not created as a replication target. Refer to Hitachi HNAS
 reference for detailed steps on how to do this;
| 2) Install and configure an OpenStack environment with default manila
 parameters and services. Refer to OpenStack manila configuration reference;
| 3) Configure HNAS parameters on manila.conf;
| 4) Prepare the network;
| 5) Configure/create share type;
| 6) Restart the services;
| 7) Configure the network.

In the following sections we cover steps 3, 4, 5, 6 and 7. Steps 1 and 2 are not
in the scope of this document.

Step 3 - HNAS Parameters Configuration
**************************************

The following parameters need to be configured in the [DEFAULT]
section of */etc/manila/manila.conf*:

+----------------------------------------------------------------------------------------------------------------------------------+
|  [DEFAULT]                                                                                                                       |
+============================+=====================================================================================================+
|          **Option**        |                                          **Description**                                            |
+----------------------------+-----------+-----------------------------------------------------------------------------------------+
|   enabled_share_backends   | Name of the section on manila.conf used to specify a backend. E.g. *enabled_share_backends = hnas1* |
+----------------------------+-----------------------------------------------------------------------------------------------------+
|   enabled_share_protocols  | Specify a list of protocols to be allowed for share creation. For Hitachi driver this must be: *NFS*|
+----------------------------+-----------------------------------------------------------------------------------------------------+

The following parameters need to be configured in the [backend] section of */etc/manila/manila.conf*:

+-------------------------------------------------------------------------------------------------------------------------------------+
|  [hnas1]                                                                                                                            |
+===============================+=====================================================================================================+
|          **Option**           |                                          **Description**                                            |
+-------------------------------+-----------------------------------------------------------------------------------------------------+
|   share_backend_name          | A name for the backend.                                                                             |
+-------------------------------+-----------------------------------------------------------------------------------------------------+
|        share_driver           | Python module path. For Hitachi driver this must be:                                                |
|                               | *manila.share.drivers.hitachi.hds_hnas.HDSHNASDriver*                                               |
+-------------------------------+-----------------------------------------------------------------------------------------------------+
| driver_handles_share_servers  | DHSS, Driver working mode. For Hitachi driver **this must be**:                                     |
|                               | *False*                                                                                             |
+-------------------------------+-----------------------------------------------------------------------------------------------------+
| hds_hnas_ip                   | HNAS management interface IP for communication between manila node and HNAS.                        |
+-------------------------------+-----------------------------------------------------------------------------------------------------+
| hds_hnas_password             | This field is used to provide password credential to HNAS.                                          |
|                               | Either hds_hnas_password or hds_hnas_ssh_private_key must be set.                                   |
+-------------------------------+-----------------------------------------------------------------------------------------------------+
| hds_hnas_ssh_private_key      | Set this parameter with RSA/DSA private key path to allow the driver to connect into HNAS.          |
+-------------------------------+-----------------------------------------------------------------------------------------------------+
| hds_hnas_evs_id               | ID or Label from EVS which this backend is assigned to (ID and Label can be                         |
|                               | listed by CLI “evs list” or EVS Management in HNAS Interface).                                      |
+-------------------------------+-----------------------------------------------------------------------------------------------------+
| hds_hnas_evs_ip               | EVS IP for mounting shares (this can be listed by CLI “evs list” or EVS Management in HNAS          |
|                               | Interface).                                                                                         |
+-------------------------------+-----------------------------------------------------------------------------------------------------+
| hds_hnas_file_system_name     | Name of the file system in HNAS, located in the specified EVS.                                      |
+-------------------------------+-----------------------------------------------------------------------------------------------------+
| hds_hnas_cluster_admin_ip0*   | If HNAS is in a multi-node cluster, set this parameter with the IP of the cluster’s admin node.     |
+-------------------------------+-----------------------------------------------------------------------------------------------------+
| hds_hnas_stalled_job_timeout* | Tree-clone-job commands are used to create snapshots and create shares from snapshots.              |
|                               | This parameter sets a timeout (in seconds) to wait for jobs to complete. Default value is           |
|                               | 30 seconds.                                                                                         |
+-------------------------------+-----------------------------------------------------------------------------------------------------+

\* Non mandatory parameters.

Below is an example of a valid configuration of HNAS driver:

| ``[DEFAULT]``
| ``enabled_share_backends = hitachi1``
| ``enabled_share_protocols = NFS``

| ``[hitachi1]``
| ``share_backend_name = HITACHI1``
| ``share_driver = manila.share.drivers.hitachi.hds_hnas.HDSHNASDriver``
| ``driver_handles_share_servers = False``
| ``hds_hnas_ip = 172.24.44.15``
| ``hds_hnas_user = supervisor``
| ``hds_hnas_password = supervisor``
| ``hds_hnas_evs_id = 1``
| ``hds_hnas_evs_ip = 10.0.1.20``
| ``hds_hnas_file_system_name = FS-Manila``

Step 4 - Prepare the Network
****************************

In the driver mode used by HNAS Driver (DHSS = False), the driver does not
handle network configuration, it is up to the administrator to configure it.
It is mandatory that HNAS management interface is reachable from Manila-Share
node through Admin Network, while the selected EVS data interface is reachable
from OpenStack Cloud, such as through Neutron Flat networking. Here is a
step-by-step of an example configuration:

| **Manila-Share Node:**
| **eth0**: Admin Network, can ping HNAS management interface.
| **eth1**: Data Network, can ping HNAS EVS IP (data interface). This interface is
 only required if you plan to use Share Migration.

| **Neutron Node and Compute Nodes:**
| **eth0**: Admin Network, can ping HNAS management interface.
| **eth1**: Data Network, can ping HNAS EVS IP (data interface).

The following image represents the described scenario:

.. image:: /images/rpc/hds_network.jpg
   :width: 60%

Run in **Neutron Node**:

| ``$ sudo ifconfig eth1 0``
| ``$ sudo ovs-vsctl add-br br-eth1``
| ``$ sudo ovs-vsctl add-port br-eth1 eth1``
| ``$ sudo ifconfig eth1 up``

Edit */etc/neutron/plugins/ml2/ml2_conf.ini* (default directory), change the
following settings as follows in their respective tags:

| ``[ml2]``
| ``type_drivers = flat,vlan,vxlan,gre``
| ``mechanism_drivers = openvswitch``

| ``[ml2_type_flat]``
| ``flat_networks = physnet1,physnet2``

| ``[ml2_type_vlan]``
| ``network_vlan_ranges = physnet1:1000:1500,physnet2:2000:2500``

| ``[ovs]``
| ``bridge_mappings = physnet1:br-ex,physnet2:br-eth1``

You may have to repeat the last line above in another file in the Compute Node,
if it exists is located in: */etc/neutron/plugins/openvswitch/ovs_neutron_plugin.ini*.

Create a route in HNAS to the tenant network. Please make sure
multi-tenancy is enabled and routes are configured per EVS. Use the command
“route-net-add” in HNAS console, where the network parameter should be the
tenant's private network, while the gateway parameter should be the FLAT
network gateway and the “console-context --evs” parameter should be the ID of
EVS in use, such as in the following example:

``$ console-context --evs 3 route-net-add --gateway 192.168.1.1 10.0.0.0/24``

Step 5 - Share Type Configuration
*********************************

Manila requires that the share type includes the driver_handles_share_servers
extra-spec. This ensures that the share will be created on a backend that
supports the requested driver_handles_share_servers capability. For the Hitachi
HNAS manila driver, this must be set to False.

``$ manila type-create hitachi False``

Step 6 - Restart the services
*****************************

Restart all manila services (manila-share, manila-scheduler and manila-api) and
neutron services (neutron-\*). This step is specific to your environment.
If you are running in devstack for example, you have to log into screen
(*screen -r*), stop the process (Ctrl^C) and run it again. If you are running it
in a distro like RHEL or SUSE, a service command (e.g. *service manila-api
restart*) is used to restart the service.

Step 7 - Configure the Network
******************************

In Neutron Controller it is necessary to create a network, a subnet and to add
this subnet interface to a router:

Create a network to the given tenant (demo), providing the DEMO_ID (this can be
fetched using *keystone tenant-list*), a name for the network, the name of the
physical network over which the virtual network is implemented and the type of
the physical mechanism by which the virtual network is implemented:

| ``$ neutron net-create --tenant-id <DEMO_ID> hnas_network``
| ``--provider:physical_network=physnet2 --provider:network_type=flat``

Create a subnet to same tenant (demo), providing the DEMO_ID (this can be fetched
using *keystone tenant-list*), the gateway IP of this subnet, a name for the
subnet, the network ID created on previously step (this can be fetched using
*neutron net-list*) and CIDR of subnet:

| ``$ neutron subnet-create --tenant-id <DEMO_ID> --gateway <GATEWAY>``
| ``--name hnas_subnet <NETWORK_ID> <SUBNET_CIDR>``

Finally, add the subnet interface to a router, providing the router ID and
subnet ID created on previously step (can be fetched using *neutron subnet-list*):

| ``$ neutron router-interface-add <ROUTER_ID> <SUBNET_ID>``

Manage and Unmanage Shares
''''''''''''''''''''''''''
Manila has the ability to manage and unmanage shares. If there is a share in
the storage and it is not in OpenStack, you can manage that share and use it
as a manila Share. HNAS drivers use virtual-volumes (V-VOL) to create shares.
Only V-VOL shares can be used by the driver. If the NFS export is an ordinary
FS export, it is not possible to use it in manila. The unmanage operation
only unlinks the share from manila. All data is preserved.

| To **manage** shares use:
| ``$ manila manage [--name <name>] [--description <description>]``
| ``[--share_type <share_type>] [--driver_options [<key=value> [<key=value> ...]]]``
| ``<service_host> <protocol> <export_path>``

Where:

+------------------+----------------------------------------------------------+
|  Parameter       | Description                                              |
+==================+==========================================================+
|                  | Manila host, backend and share name. e.g.                |
|  service_host    | ubuntu\@hitachi1#HITACHI1. The available hosts can be    |
|                  | listed with the command: *manila pool-list* (admin only).|
+------------------+---------------------+------------------------------------+
|  protocol        | NFS, it is the only supported protocol in this driver    |
|                  | version.                                                 |
+------------------+----------------------------------------------------------+
|  export_path     | The export path of the share.                            |
|                  | e.g. *172.24.44.31:/shares/some_share_id*                |
+------------------+----------------------------------------------------------+


| To **unmanage** a share use:
| ``$ manila unmanage <share_id>``

Where:

+------------------+---------------------------------------------------------+
|  Parameter       | Description                                             |
+==================+=========================================================+
|   share_id       | Manila ID of the share to be unmanaged. This list can   |
|                  | be fetched with: *manila list*.                         |
+------------------+---------------------+-----------------------------------+

Additional Notes:
*****************

| - HNAS has some restrictions about the number of EVSs, filesystems,
 virtual-volumes and simultaneous SSC connections. Check the manual
 specification for your system.
| - Shares and snapshots are thin provisioned. It is reported to manila only the
 real used space in HNAS. Also, a snapshot does not initially take any space in
 HNAS, it only stores the difference between the share and the snapshot, so it
 grows when share data is changed.
| - Admins should manage the tenant’s quota (*manila quota-update*) to control the
 backend usage.

The :mod:`manila.share.drivers.hitachi.hds_hnas` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.hitachi.hds_hnas
   :noindex:
   :members:
   :undoc-members:
   :show-inheritance:
