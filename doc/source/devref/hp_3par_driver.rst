..
      Copyright 2015 Hewlett Packard Development Company, L.P.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

           http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

HP 3PAR Driver
==============

The HP 3PAR Manila driver provides NFS and CIFS shared file systems to
OpenStack using HP 3PAR's File Persona capabilities.

Supported Operations
--------------------

The following operations are supported with HP 3PAR File Persona:

- Create/delete NFS and CIFS shares

  * Shares are not accessible until access rules allow access

- Allow/deny NFS share access

  * IP access rules are required for NFS share access
  * User access rules are not allowed for NFS shares
  * Access level (RW/RO) is ignored
  * Shares created from snapshots are always read-only
  * Shares not created from snapshots are read-write (and subject to ACLs)

- Allow/deny CIFS share access

  * Both IP and user access rules are required for CIFS share access
  * User access requires a 3PAR local user (LDAP and AD is not yet supported)
  * Access level (RW/RO) is ignored
  * Shares created from snapshots are always read-only
  * Shares not created from snapshots are read-write (and subject to ACLs)

- Create/delete snapshots
- Create shares from snapshots

  * Shares created from snapshots are always read-only

Share networks are not supported. Shares are created directly on the 3PAR
without the use of a share server or service VM. Network connectivity is
setup outside of Manila.

Requirements
------------

On the system running the Manila share service:

- hp3parclient version 3.2.1 or newer from PyPI

On the HP 3PAR array:

- HP 3PAR Operating System software version 3.2.1 MU3 or higher
- A license that enables the File Persona feature
- The array class and hardware configuration must support File Persona

Pre-Configuration on the HP 3PAR
--------------------------------

- HP 3PAR File Persona must be initialized and started (:code:`startfs`)
- A File Provisioning Group (FPG) must be created for use with Manila
- A Virtual File Server (VFS) must be created for the FPG
- The VFS must be configured with an appropriate share export IP address
- A local user in the Administrators group is needed for CIFS shares

Backend Configuration
---------------------

The following parameters need to be configured in the Manila configuration
file for the HP 3PAR driver:

- `share_backend_name` = <backend name to enable>
- `share_driver` = manila.share.drivers.hp.hp_3par_driver.HP3ParShareDriver
- `driver_handles_share_servers` = False
- `hp3par_fpg` = <FPG to use for share creation>
- `hp3par_share_ip_address` = <IP address to use for share export location>
- `hp3par_san_ip` = <IP address for SSH access to the SAN controller>
- `hp3par_api_url` = <3PAR WS API Server URL>
- `hp3par_username` = <3PAR superuser username>
- `hp3par_password` = <3PAR superuser password>
- `hp3par_san_login` = <Username for SSH access to the SAN controller>
- `hp3par_san_password` = <Password for SSH access to the SAN controller>
- `hp3par_debug` = <False or True for extra debug logging>

The `hp3par_share_ip_address` must be a valid IP address for the configured
FPG's VFS. This IP address is used in export locations for shares that are
created. Networking must be configured to allow connectivity from clients to
shares.

Restart of :term:`manila-share` service is needed for the configuration changes to take
effect.

Network Approach
----------------

Connectivity between the storage array (SSH/CLI and WSAPI) and the Manila host
is required for share management.

Connectivity between the clients and the VFS is required for mounting
and using the shares. This includes:

- Routing from the client to the external network
- Assigning the client an external IP address (e.g., a floating IP)
- Configuring the Manila host networking properly for IP forwarding
- Configuring the VFS networking properly for client subnets

The :mod:`manila.share.drivers.hp.hp_3par_driver` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.hp.hp_3par_driver
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:
