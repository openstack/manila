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

HPE 3PAR Driver
===============

The HPE 3PAR manila driver provides NFS and CIFS shared file systems to
OpenStack using HPE 3PAR's File Persona capabilities.

.. note::
    In OpenStack releases prior to Mitaka this driver was called the
    HP 3PAR driver. The Liberty configuration reference can be found
    at: http://docs.openstack.org/liberty/config-reference/content/hp-3par-share-driver.html

Supported Operations
--------------------

The following operations are supported with HPE 3PAR File Persona:

- Create/delete NFS and CIFS shares

  * Shares are not accessible until access rules allow access

- Allow/deny NFS share access

  * IP access rules are required for NFS share access

- Allow/deny CIFS share access

  * CIFS shares require user access rules.
  * User access requires a 3PAR local or AD user (LDAP is not yet supported)

- Create/delete snapshots
- Create shares from snapshots

Share networks are not supported. Shares are created directly on the 3PAR
without the use of a share server or service VM. Network connectivity is
setup outside of manila.

Requirements
------------

On the system running the manila share service:

- python-3parclient 4.2.0 or newer from PyPI.

On the HPE 3PAR array:

- HPE 3PAR Operating System software version 3.2.1 MU3 or higher
- A license that enables the File Persona feature
- The array class and hardware configuration must support File Persona

Pre-Configuration on the HPE 3PAR
---------------------------------

- HPE 3PAR File Persona must be initialized and started (:code:`startfs`)
- A File Provisioning Group (FPG) must be created for use with manila
- A Virtual File Server (VFS) must be created for the FPG
- The VFS must be configured with an appropriate share export IP address
- A local user in the Administrators group is needed for CIFS shares

Backend Configuration
---------------------

The following parameters need to be configured in the manila configuration
file for the HPE 3PAR driver:

- `share_backend_name` = <backend name to enable>
- `share_driver` = manila.share.drivers.hpe.hpe_3par_driver.HPE3ParShareDriver
- `driver_handles_share_servers` = False
- `hpe3par_fpg` = <FPG to use for share creation>
- `hpe3par_share_ip_address` = <IP address to use for share export location>
- `hpe3par_san_ip` = <IP address for SSH access to the SAN controller>
- `hpe3par_api_url` = <3PAR WS API Server URL>
- `hpe3par_username` = <3PAR username with the 'edit' role>
- `hpe3par_password` = <3PAR password for the user specified in hpe3par_username>
- `hpe3par_san_login` = <Username for SSH access to the SAN controller>
- `hpe3par_san_password` = <Password for SSH access to the SAN controller>
- `hpe3par_debug` = <False or True for extra debug logging>
- `hpe3par_cifs_admin_access_username` = <CIFS admin user name>
- `hpe3par_cifs_admin_access_password` = <CIFS admin password>
- `hpe3par_cifs_admin_access_domain` = <CIFS admin domain>
- `hpe3par_share_mount_path` = <Full path to mount shares>

The `hpe3par_share_ip_address` must be a valid IP address for the configured
FPG's VFS. This IP address is used in export locations for shares that are
created. Networking must be configured to allow connectivity from clients to
shares.

`hpe3par_cifs_admin_access_username` and `hpe3par_cifs_admin_access_password`
must be provided to delete nested CIFS shares. If they are not, the share
contents will not be deleted. `hpe3par_cifs_admin_access_domain` and
`hpe3par_share_mount_path` can be provided for additional configuration.

Restart of :term:`manila-share` service is needed for the configuration changes to take
effect.

Backend Configuration for AD user
---------------------------------

The following parameters need to be configured through HPE 3PAR CLI to access
file share using AD.

Set authentication parameters::

    $ setauthparam ldap-server IP_ADDRESS_OF_AD_SERVER
    $ setauthparam binding simple
    $ setauthparam user-attr AD_DOMAIN_NAME\\
    $ setauthparam accounts-dn CN=Users,DC=AD,DC=DOMAIN,DC=NAME
    $ setauthparam account-obj user
    $ setauthparam account-name-attr sAMAccountName
    $ setauthparam memberof-attr memberOf
    $ setauthparam super-map CN=AD_USER_GROUP,DC=AD,DC=DOMAIN,DC=NAME

Verify new authentication parameters set as expected::

    $ showauthparam

Verify AD users set as expected::

    $ checkpassword AD_USER

Command result should show ``user AD_USER is authenticated and authorized``
message on successful configuration.

Add 'ActiveDirectory' in authentication providers list::

    $ setfs auth ActiveDirectory Local

Verify authentication provider list shows 'ActiveDirectory'::

    $ showfs -auth

Set/Add AD user on FS::

    $ setfs ad –passwd PASSWORD AD_USER AD_DOMAIN_NAME

Verify FS user details::

    $ showfs -ad

Example of using AD user to access CIFS share
---------------------------------------------

Pre-requisite:

- Share type should be configured for 3PAR backend

Create a CIFS file share with 2GB of size::

    $ manila create --name FILE_SHARE_NAME --share-type SHARE_TYPE CIFS 2

Check file share created as expected::

    $ manila show FILE_SHARE_NAME

Configuration to provide share access to AD user::

    $ manila access-allow FILE_SHARE_NAME user AD_DOMAIN_NAME\\\\AD_USER
      --access-level rw

Check users permission set as expected::

    $ manila access-list FILE_SHARE_NAME

The AD_DOMAIN_NAME\\AD_USER must be listed in access_to column and should
show active in its state column as result of this command.

Network Approach
----------------

Connectivity between the storage array (SSH/CLI and WSAPI) and the manila host
is required for share management.

Connectivity between the clients and the VFS is required for mounting
and using the shares. This includes:

- Routing from the client to the external network
- Assigning the client an external IP address (e.g., a floating IP)
- Configuring the manila host networking properly for IP forwarding
- Configuring the VFS networking properly for client subnets

Share Types
-----------

When creating a share, a share type can be specified to determine where and
how the share will be created. If a share type is not specified, the
`default_share_type` set in the manila configuration file is used.

Manila requires that the share type includes the
`driver_handles_share_servers` extra-spec. This ensures that the share
will be created on a backend that supports the requested
driver_handles_share_servers (share networks) capability.
For the HPE 3PAR driver, this must be set to False.

Another common manila extra-spec used to determine where a share is created
is `share_backend_name`. When this extra-spec is defined in the share type,
the share will be created on a backend with a matching share_backend_name.

The HPE 3PAR driver automatically reports capabilities based on the FPG used
for each backend. Share types with extra specs can be created by an
administrator to control which share types are allowed to use FPGs with or
without specific capabilities. The following extra-specs are used with
the capabilities filter and the HPE 3PAR driver:

- `hpe3par_flash_cache` = '<is> True' or '<is> False'
- `thin_provisioning` = '<is> True' or '<is> False'
- `dedupe` = '<is> True' or '<is> False'

`hpe3par_flash_cache` will be reported as True for backends that have
3PAR's Adaptive Flash Cache enabled.

`thin_provisioning` will be reported as True for backends that use thin
provisioned volumes. FPGs that use fully provisioned volumes will report
False. Backends that use thin provisioning also support manila's
over-subscription feature.

`dedupe` will be reported as True for backends that use deduplication
technology.

Scoped extra-specs are used to influence vendor-specific implementation
details. Scoped extra-specs use a prefix followed by a colon.  For HPE 3PAR
these extra-specs have a prefix of `hpe3par`. For HP 3PAR these extra-specs
have a prefix of `hp3par`.

The following HPE 3PAR extra-specs are used when creating CIFS (SMB) shares:

- `hpe3par:smb_access_based_enum` = true or false
- `hpe3par:smb_continuous_avail` = true or false
- `hpe3par:smb_cache` = off, manual, optimized or auto


`smb_access_based_enum` (Access Based Enumeration) specifies if users can see
only the files and directories to which they have been allowed access on the
shares. The default is `false`.

`smb_continuous_avail` (Continuous Availability) specifies if SMB3 continuous
availability features should be enabled for this share. If not specified,
the default is `true`. This setting will be ignored with hp3parclient 3.2.1
or earlier.

`smb_cache` specifies client-side caching for offline files. Valid values are:

* `off`: The client must not cache any files from this share. The share is
  configured to disallow caching.
* `manual`: The client must allow only manual caching for the files open from
  this share.
* `optimized`: The client may cache every file that it opens from
  this share. Also, the client may satisfy the file requests from its
  local cache. The share is configured to allow automatic caching
  of programs and documents.
* `auto`: The client may cache every file that it opens from this
  share. The share is configured to allow automatic caching of
  documents.
* If this is not specified, the default is `manual`.

The following HPE 3PAR extra-specs are used when creating NFS shares:

- `hpe3par:nfs_options` = Comma separated list of NFS export options

The NFS export options have the following limitations:

  * `ro` and `rw` are not allowed (manila will determine the read-only option)
  * `no_subtree_check` and `fsid` are not allowed per HPE 3PAR CLI support
  * `(in)secure` and `(no_)root_squash` are not allowed because the HPE 3PAR
    driver controls those settings

All other NFS options are forwarded to the HPE 3PAR as part of share creation.
The HPE 3PAR will do additional validation at share creation time. Refer to
HPE 3PAR CLI help for more details.

Delete Nested Shares
--------------------

When a nested share is deleted (nested shares will be created when
``hpe_3par_fstore_per_share`` is set to ``False``), the file tree also
attempts to be deleted.

With NFS shares, there is no additional configuration that needs to be done.

For CIFS shares, ``hpe3par_cifs_admin_access_username`` and
``hpe3par_cifs_admin_access_password`` must be provided. If they are omitted,
the original functionality is honored and the file tree remains untouched.
``hpe3par_cifs_admin_access_domain`` and ``hpe3par_share_mount_path`` can also
be specified to create further customization.

The :mod:`manila.share.drivers.hpe.hpe_3par_driver` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.hpe.hpe_3par_driver
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:
