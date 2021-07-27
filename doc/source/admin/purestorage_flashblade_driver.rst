..
      Copyright 2021 Pure Storage Inc.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

           http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.


===================================================
Pure Storage FlashBlade Driver for OpenStack Manila
===================================================

The Pure Storage FlashBlade Manila driver provides NFS shared file systems to
OpenStack using Pure Storage's FlashBlade native filesystem capabilities.

Supported Operations
~~~~~~~~~~~~~~~~~~~~

The following operations are supported with Pure Storage FlashBlade:

- Create/delete NFS shares

  * Shares are not accessible until access rules allow access

- Allow/deny NFS share access

  * IP access rules are required for NFS share access

- Create/delete snapshots
- Expand and Shrink shares
- Revert to Snapshot

Share networks are not supported. Shares are created directly on the FlashBlade
without the use of a share server or service VM. Network connectivity is
setup outside of Manila.

General Requirements
~~~~~~~~~~~~~~~~~~~~

On the system running the Manila share service:

- purity_fb 1.12.1 or newer from PyPI.

On the Pure Storage FlashBlade:

- Purity//FB Operating System software version 2.3.0 or higher

Network Requirements
~~~~~~~~~~~~~~~~~~~~

Connectivity between the FlashBlade (REST) and the manila host
is required for share management.

Connectivity between the clients and the FlashBlade is required for mounting
and using the shares. This includes:

- Routing from the client to the external network
- Assigning the client an external IP address (e.g., a floating IP)
- Configuring the manila host networking properly for IP forwarding
- Configuring the FlashBlade networking properly for client subnets

Driver Configuration
~~~~~~~~~~~~~~~~~~~~

Before configuring the driver, make sure the following networking requirements
have been met:

- A management subnet must be accessible from the system running the Manila
  share services
- A data subnet must be accessible from the system running the Nova compute
  services
- An API token must be available for a user with administrative privileges

Perform the following steps:

#. Configure the Pure Storage FlashBlade parameters in `manila.conf`
#. Configure/create a share type
#. Restart the services

It is also assumed that the OpenStack networking has been confiured correctly.

Step 1 - FlashBlade Parameters configuration
********************************************

The following parameters need to be configured in the [DEFAULT] section
of `/etc/manila/manila.conf`:

+----------------------------+------------------------------------------------+
|          **Option**        |               **Description**                  |
+============================+================================================+
| enabled_share_backends     | Name of the section on ``manila.conf`` used to |
|                            | specify a backend. For example:                |
|                            | *enabled_share_backends = flashblade*          |
+----------------------------+------------------------------------------------+
| enabled_share_protocols    | Specify a list of protocols to be allowed for  |
|                            | share creation. This driver version only       |
|                            | supports NFS                                   |
+----------------------------+------------------------------------------------+

The following parameters need to be configured in the [backend] section
of ``/etc/manila/manila.conf``:

+-------------------------------------------------+-----------------------------------------------------------------------------------------------------+
|                  **Option**                     |                                          **Description**                                            |
+=================================================+=====================================================================================================+
| share_backend_name                              | A name for the backend.                                                                             |
+-------------------------------------------------+-----------------------------------------------------------------------------------------------------+
| share_driver                                    | Python module path. For this driver **this must be**:                                               |
|                                                 | *manila.share.drivers.purestorage.flashblade.FlashBladeShareDriver*                                 |
+-------------------------------------------------+-----------------------------------------------------------------------------------------------------+
| driver_handles_share_servers                    | Driver working mode. For this driver **this must be**:                                              |
|                                                 | *False*.                                                                                            |
+-------------------------------------------------+-----------------------------------------------------------------------------------------------------+
| flashblade_mgmt_vip                             | The name (or IP address) for the Pure Storage FlashBlade storage system management VIP.             |
+-------------------------------------------------+-----------------------------------------------------------------------------------------------------+
| flashblade_data_vip                             | The name (or IP address) for the Pure Storage FlashBlade storage system data VIP.                   |
+-------------------------------------------------+-----------------------------------------------------------------------------------------------------+
| flashblade_api                                  | API token for an administrative user account                                                        |
+-------------------------------------------------+-----------------------------------------------------------------------------------------------------+
| flashblade_eradicate (Optional)                 | When enabled, all FlashBlade file systems and snapshots will be eradicated at the time              |
|                                                 | of deletion in Manila. Data will NOT be recoverable after a delete with this set to True!           |
|                                                 | When disabled, file systems and snapshots will go into pending eradication state and can be         |
|                                                 | recovered. Default value is *True*.                                                                 |
+-------------------------------------------------+-----------------------------------------------------------------------------------------------------+

Below is an example of a valid configuration of the FlashBlade driver:

.. code-block:: ini

   [DEFAULT]
   ...
   enabled_share_backends = flashblade
   enabled_share_protocols = NFS
   ...

   [flashblade]
   share_backend_name = flashblade
   share_driver = manila.share.drivers.purestorage.flashblade.FlashBladeShareDriver
   driver_handles_share_servers = False
   flashblade_mgmt_vip = 1.2.3.4
   flashblade_data_vip = 1.2.3.5
   flashblade_api = T-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

Restart of :term:`manila-share` service is needed for the configuration changes to take
effect.

Step 2 - Share Type Configuration
*********************************

Shared File Systems service requires that the share type includes the
driver_handles_share_servers extra-spec. This ensures that the share will be
created on a backend that supports the requested driver_handles_share_servers
capability. For the Pure Storage FlashBlade Driver for OpenStack this must be
set to False.

.. code-block:: console

   $ manila type-create flashblade False

Additionally, the driver also reports the following common capabilities that
can be specified in the share type:

+----------------------------------+------------------------------------------------------+
|        **Capability**            |             **Description**                          |
+==================================+======================================================+
| thin_provisioning = True         | All shares created on FlashBlade are always thin     |
|                                  | provisioned. If you set it this, the value           |
|                                  | **must be**: *True*.                                 |
+----------------------------------+------------------------------------------------------+
| snapshot_support = True/False    | FlashBlade supports share snapshots.                 |
|                                  | If you set this, the value **must be**: *True*.      |
+----------------------------------+------------------------------------------------------+
| revert_to_snapshot = True/False  | FlashBlade supports reverting a share to the latest  |
|                                  | available snapshot. If you set this, the value       |
|                                  | **must be**: *True*.                                 |
+----------------------------------+------------------------------------------------------+

To specify a common capability on the share type, use the *type-key* command,
for example:

.. code-block:: console

   $ manila type-key flashblade set snapshot_support=True
   $ manila type-key flashblade set revert_to_snapshot=True

Step 3 - Restart the Services
*****************************

Restart all Shared File Systems services (manila-share, manila-scheduler and
manila-api). This step is specific to your environment. for example,
`systemctl restart <controller>@manila-shr` is used to restart the share service.

The :mod:`manila.share.drivers.purestorage.flashblade` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.purestorage.flashblade
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:
