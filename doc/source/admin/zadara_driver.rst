..
      Copyright (c) 2021 Zadara Inc.
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

=======================================
Zadara VPSA Driver for OpenStack Manila
=======================================

`Zadara’s <https://www.zadara.com>`__ Virtual Private Storage Array (VPSA)
is the first software defined, Enterprise-Storage-as-a-Service. It is an
elastic and private block and file storage system which provides
enterprise-grade data protection and data management storage services.

Manila VPSA driver provides a seamless management capabilities for VPSA
volumes, in this case, NFS & SMB volumes without losing the added value
provided by the VPSA Storage Array/Flash-Array.

Requirements
------------

- VPSA Storage Array/Flash-Array running version 20.12 or higher.

- Networking preparation - the Zadara VPSA driver for Manila support DHSS=False
  (driver_handles_share_servers), the driver does not handle
  the network configuration, it is up to the administrator to ensure
  connectivity from a manila-share node and the Openstack cloud to the
  VPSA Front-End network (such as neutron flat/VLAN network).

Supported shared filesystems and operations
-------------------------------------------

Share file system supported
~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  SMB (CIFS)
-  NFS

Supported operations
~~~~~~~~~~~~~~~~~~~~

The following operations are supported:

-  Create a share.
-  Delete a share.
-  Extend a share.
-  Create a snapshot.
-  Delete a snapshot.
-  Create a share from snapshot.
-  Allow share access.
-  Manage a share.

.. note::

   - Only IP access type is supported
   - Both RW and RO access levels supported


Backend Configuration
~~~~~~~~~~~~~~~~~~~~~

The following parameters need to be configured in the [DEFAULT] section of
manila configuration (/etc/manila/manila.conf):

- `enabled_share_backends` = Name of the section on manila.conf used to specify
  a backend i.e. *enabled_share_backends = zadaravpsa*

- `enabled_share_protocols` - Specify a list of protocols to be allowed for
  share creation. The VPSA driver support the following options: *NFS* or
  *CIFS* or *NFS, CIFS*

The following parameters need to be configured in the [backend] section of
manila configuration (/etc/manila/manila.conf):

Driver options
--------------

- `zadara_vpsa_host` = <VPSA - Management Host name or IP address>
- `zadara_vpsa_port` = <VPSA - Port number>
- `zadara_vpsa_use_ssl` = <VPSA - Use SSL connection (default=False)
- `zadara_ssl_cert_verify` = <If set to True the http client will validate
  the SSL certificate of the VPSA endpoint (default=True)>
- `zadara_driver_ssl_cert_path` = <Can be used to specify a non default path
  to a CA_BUNDLE file or directory with certificates of trusted CAs
  (default=None)
- `zadara_access_key` - <VPSA access key>
- `zadara_vpsa_poolname` - <VPSA - Storage Pool assigned for volumes>
- `zadara_vol_encrypt` = <VPSA - Default encryption policy for volumes
  (default = True)
- `zadara_gen3_vol_dedupe` = <VPSA - Default encryption policy for volumes
  (default = True)>
- `zadara_gen3_vol_compress` = <VPSA - Enable compression for volumes
  (default=False)>
- `zadara_share_name_template` = <VPSA - Default template for VPSA share names
  (default=‘OS_share-%s’>
- `zadara_share_snap_name_template` = <VPSA - Default template for VPSA share
  snapshot names (default=‘OS_share-snapshot-%s’)
- `zadara_default_snap_policy` = <VPSA - Attach snapshot policy for volumes
  (default=False)>
- `driver_handles_share_servers` = <DHSS, driver working mode (must be set
  to False)>
- `share_driver` = manila.share.drivers.zadara.zadara.ZadaraVPSAShareDriver

Back-end configuration example
------------------------------

.. code-block:: ini

   [DEFAULT]
   enabled_share_backends = zadaravpsa
   enabled_share_protocols = NFS,CIFS

   [zadaravpsa]
   driver_handles_share_servers = False
   zadara_vpsa_host = vsa-00000010-mycloud.zadaravpsa.com
   zadara_vpsa_port = 443
   zadara_access_key = MYSUPERSECRETACCESSKEY
   zadara_vpsa_poolname = pool-00010001
   share_backend_name = zadaravpsa
   zadara_vpsa_use_ssl = true
   share_driver = manila.share.drivers.zadara.zadara.ZadaraVPSAShareDriver
