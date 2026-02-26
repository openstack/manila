====================================
HPE Alletra MP B10000 Share Driver
====================================

The HPE Alletra MP B10000 Manila driver provides NFS file services
to OpenStack using the HPE Alletra MP B10000 file service capabilities.

Supported shared filesystems
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The driver supports NFS shares.

Operations supported
~~~~~~~~~~~~~~~~~~~~

- Create a share.

- Delete a share.

- Allow share access.

- Deny share access.

- Extend a share.

- Manage an existing share.

- Unmanage a share.

Requirements
~~~~~~~~~~~~

On the HPE Alletra MP B10000 array:

- HPE Alletra MP B10000 Operating System software version 10.5.0 or higher

- Fileservice must be enabled after configuring file ports.

Pre-configuration on HPE Alletra MP B10000
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Before configuring the manila driver, the HPE Alletra MP B10000 array must be
properly set up:

- Required File ports must be configured. If File ports are not already configured, follow these steps:

  To change the port persona to File, run the ``showport`` command and check if slot 4 ports 1 & 2 are
  NVMe or iSCSI ports.

  If the ports are iSCSI, run the following commands to delete and configure them as file ports:

  .. code-block:: console

     $ controliscsiport delete 0:4:1
     $ controliscsiport delete 0:4:2
     $ controliscsiport delete 1:4:1
     $ controliscsiport delete 1:4:2

  If the ports are NVMe, run the following commands to delete and configure them as file ports:

  .. code-block:: console

     $ controlport nvme delete 0:4:1
     $ controlport nvme delete 0:4:2
     $ controlport nvme delete 1:4:1
     $ controlport nvme delete 1:4:2

  Once the ports are configured as file persona ports for slot 4, ports 1 and 2, reboot the cluster:

  .. code-block:: console

     $ shutdownsys reboot

  After the cluster comes up, assign IP addresses to all the ports (0:4:1, 0:4:2, 1:4:1, 1:4:2).

- File service must be supported and enabled on the array

  .. code-block:: console

     $ showfileservice
     $ setfileservice enable

- Verify the WSAPI service is enabled and running

  .. code-block:: console

     $ showwsapi

- The array must have appropriate network configuration for client access

Driver configuration
~~~~~~~~~~~~~~~~~~~~

The Manila configuration file (typically ``/etc/manila/manila.conf``)
defines and configures the Manila drivers and backends. After updating the
configuration file, the Manila share service must be restarted for changes
to take effect.

The following table contains the configuration options specific to the
HPE Alletra MP B10000 share driver.

.. include:: ../../tables/manila-hpealletra.inc

#. ``Enable share protocols``

   To enable NFS share protocol, ensure that NFS is included in the
   ``enabled_share_protocols`` setting in the ``DEFAULT`` section of the
   ``manila.conf`` file.

   .. code-block:: ini

      [DEFAULT]
      enabled_share_protocols = NFS

#. ``Enable share backends``

   In the ``[DEFAULT]`` section of the Manila configuration file, use the
   ``enabled_share_backends`` option to specify the name of one or more
   backend configuration sections to be enabled. To enable multiple
   backends, use a comma-separated list.

   .. code-block:: ini

      [DEFAULT]
      enabled_share_backends = hpealletra1

   .. note::

      The name of the backend's configuration section is used (which may
      be different from the ``share_backend_name`` value).

   For the backend, a configuration section defines the driver and backend
   options. These include common Manila options, as well as driver-specific
   options.

#. ``Driver Specific Configurations``

   The following driver-specific options must be configured:

   - ``hpealletra_wsapi_url``: The WSAPI V3 URL to the Alletra MP B10000.
     Must be in the format ``https://<alletra_ip>:8080/api/v3``.

   - ``hpealletra_username``: Backend username with appropriate permissions.
     The user must have the 'super' or 'edit' role for file service management.

   - ``hpealletra_password``: Password for the user specified in
     ``hpealletra_username``.

   - ``hpealletra_debug``: Boolean value. If set to ``True``, WSAPI V3 API
     request and response logs will be displayed. Default is ``False``.

   .. note::

      The driver uses HTTPS for secure communication with the array.
      Ensure that the Manila host can establish HTTPS connections to the
      array's WSAPI endpoint.

#. ``Example Configuration``

   The following parameters show a sample subset of the ``manila.conf`` file
   which configures a backend for HPE Alletra MP B10000:

   .. code-block:: ini

      [DEFAULT]
      enabled_share_backends = hpealletra1
      enabled_share_protocols = NFS

      [hpealletra1]
      share_driver = manila.share.drivers.hpe.alletra_mp_b10000.hpe_alletra_driver.HPEAlletraMPB10000ShareDriver
      share_backend_name = hpealletra1
      driver_handles_share_servers = False
      hpealletra_wsapi_url = https://192.168.1.100:8080/api/v3
      hpealletra_username = <username>
      hpealletra_password = <password>
      hpealletra_debug = False

#. ``Restart manila-share service``

   After updating the configuration file, restart the Manila share service
   for changes to take effect:

Network Requirements
~~~~~~~~~~~~~~~~~~~~

Network connectivity between the Manila host and storage array (WSAPI Endpoints)
is required for share management. The Manila share service must be able to
reach the WSAPI endpoint configured in ``hpealletra_wsapi_url``.

Network connectivity between clients and the array's file ports is required
for mounting and using the shares.

The HPE Alletra MP B10000 driver does not support share networks
(supporting only ``driver_handles_share_servers=False`` option). Network
connectivity for share access must be configured outside of Manila.

Share types
~~~~~~~~~~~

When creating a share, the share type will be used to determine where and how
the share will be created.

Manila requires that the share type includes the ``driver_handles_share_servers``
extra-spec. This ensures that the share is created on a backend that supports
the requested driver_handles_share_servers (share networks) capability. For the
HPE Alletra MP B10000 driver, this option must be set to ``False``.

Another common Manila extra-spec used to determine where a share is created
is ``share_backend_name``. When this extra-spec is defined in the share type,
the share will be created on a backend with a matching ``share_backend_name``.

To create a share type for the HPE Alletra MP B10000 backend:

.. code-block:: console

   $ openstack share type create alletra_nfs False
   $ openstack share type set alletra_nfs --extra-specs share_backend_name=hpealletra1


Share type additional specs
---------------------------

The following driver-specific additional specs are supported by Alletra MP B10000.

#. ``hpe_alletra_b10000:reduce``

   When the value is set to ``true`` (or ``false``), shares of
   this reduce type are created on the backend. The reduce setting is applied
   at share creation time and cannot be changed for existing shares.

   The ``reduce`` parameter is used to control the ``compression`` and ``dedup`` capabilities
   of the share.

   | If reduce = true, compression = true & dedup = true.
   | If reduce = false, compression = false & dedup = false.

   The reduce value can be controlled by including the reduce key as part of the
   share type. If the reduce key is not provided, its value defaults to ``true``.

   Alternatively, you can use the ``compression`` and ``dedupe`` parameters
   directly instead of ``reduce``, but you cannot specify both ``reduce`` and
   ``compression``/``dedupe`` in the same share type.

   Example using reduce:

   .. code-block:: console

      $ openstack share type set alletra_nfs --extra-specs hpe_alletra_b10000:reduce=true

   Example using compression and dedupe as alternative:

   .. code-block:: console

      $ openstack share type set alletra_nfs --extra-specs compression=true dedupe=true

#. ``hpe_alletra_b10000:squash_option``

   The value can be set to ``root_squash``, ``all_squash``, or
   ``no_root_squash``. Any access rules which are added to the alletra
   backend will be created with this squash option. If the share type is modified
   to change the squash option, the next share access rule update will use
   the new squash option value.

   The squash option of all access rules is controlled through this key. If it
   is not provided, the squash option defaults to ``root_squash``.

   Example:

   .. code-block:: console

      $ openstack share type set alletra_nfs --extra-specs hpe_alletra_b10000:squash_option=root_squash

The following common additional specs are also supported by Alletra MP B10000:

#. ``compression``

   Controls whether compression is enabled on the share.

   When specifying ``compression``, you must also specify ``dedupe`` with the
   same value (both ``true`` or both ``false``). You cannot use ``compression``
   together with ``hpe_alletra_b10000:reduce``.

   Example:

   .. code-block:: console

      $ openstack share type set alletra_nfs --extra-specs compression=true dedupe=true

#. ``dedupe``

   Controls whether data deduplication is enabled on the share.

   When specifying ``dedupe``, you must also specify ``compression`` with the
   same value (both ``true`` or both ``false``). You cannot use ``dedupe``
   together with ``hpe_alletra_b10000:reduce``.

   Example:

   .. code-block:: console

      $ openstack share type set alletra_nfs --extra-specs dedupe=true compression=true

#. ``thin_provisioning``

   Controls whether thin provisioning is enabled on the share.

   This extra spec must be set to ``true`` or not specified at all. Setting
   it to ``false`` is not supported by this driver.

   Example:

   .. code-block:: console

      $ openstack share type set alletra_nfs --extra-specs thin_provisioning=true

.. note::

   Modifying share type extra specs after shares have been created is not
   recommended, as it will cause inconsistency between the share type
   definition and the actual backend share properties. Backend share
   characteristics like reduce, compression, and dedupe cannot be changed
   after creation.

Supported Features
~~~~~~~~~~~~~~~~~~

Creating and deleting shares
----------------------------

Refer to :ref:`share operations <shared_file_systems_crud_share>`
for CLI commands and more information.

.. note::

   If a share contains data, the delete operation will fail. The error will be
   reported in the Manila logs and the share will be in ``error_deleting`` state.
   Ensure the share is empty before attempting to delete it.

Share access
------------

A share must have access rules configured before it can be accessed by clients.
IP-based access rules are required for NFS shares.

.. note::

   When no Manila access rules are configured, the driver will block all IP addresses
   by setting a default access rule of 0.0.0.0 with read-only and root_squash
   permissions on the backend Alletra B10000 array. You must explicitly create
   access rules to allow client access.

For CLI commands and more information on managing access rules,
see :ref:`manage access to share <access_to_share>`.

Share extend
------------

Share extend operation is supported by the driver.

For CLI commands and more information on extending shares,
see :ref:`share resize <shared_file_systems_share_resize>`.

.. note::

   The share size shown in Manila includes filesystem metadata and other overhead.
   Client-usable space will be less than the displayed share size.

.. note::

   Share shrink is not currently supported by this driver.

Ensure shares
-------------

The driver supports ensure_shares operation, which validates that shares
exist on the backend and updates their status in Manila. Shares found on
the backend are updated with the latest export locations. Shares not found
on the backend are marked with error state.

The ensure_shares operation for the driver is executed only in case of
service restarts after configuration changes in /etc/manila/manila.conf.

If the backend fileshare export path changes due to file port IP change
or other reasons, the administrator must manually trigger the ensure shares
command in OpenStack to update the latest export paths.

Refer to :ref:`recalculating the shares export location <shared_file_systems_services_manage.rst>`
for details on manually triggering the ensure shares operation.

Manage and unmanage
-------------------

The driver supports the ability to bring an existing share on the HPE Alletra
array into Manila management. When managing a share, the driver validates that
the share exists on the backend before bringing it into manila management.

Certain metadata requirements must be satisfied in order to manage an existing share:

- If backend share ``reduce`` value does not match with the ``hpe_alletra_b10000:reduce``
  value from the share type, manage share operation will fail. We must associate the
  correct share type with the share. Default reduce value in case share type does not
  have this key is true. Similarly, if the share type uses ``compression`` and ``dedupe``
  parameters instead of ``reduce``, those values must also match the backend share's
  compression and deduplication settings.

- The backend share must have either an empty access rules list or only the default
  0.0.0.0 access rule with read-only and root_squash. If other access rules exist in
  the backend sharesettings (access rules) list, the manage share operation will fail.
  Administrator must clear all such access rules from the backend share before performing
  manage share operation again.

  .. code-block:: console

      $ setsharesetting -remove <ipaddr_list> <sharesetting_name>

- The filesystem size of the backend fileshare must be a multiple of 1024MiB (1GiB).
  If it is not the manage operation will fail. Manila logs will contain details on how
  much MiB to expand the backend filesystem by to bring it to a multiple of 1024MiB.
  After that manage operation can be tried again.

  To expand size by 500 MiB:

  .. code-block:: console

      $ setfilesystem -size 500 <filesystem_name>

When unmanage share operation is performed, the driver removes the share from Manila
management but leaves the share intact on the backend array.

Refer to :ref:`manage and unmanage share <shared_file_systems_manage_and_unmanage_share>`
for CLI commands and more information.

Restrictions and limitations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Only NFS protocol is supported. CIFS/SMB is not supported.
- Share networks are not supported (driver_handles_share_servers must be False).
- Share shrink is not currently supported.
- Share migration is not supported.
- Share replication is not supported.
- Share groups and consistency groups are not supported.
- Security services (LDAP, Active Directory, Kerberos) are not supported.
- Only IP-based access rules are supported for NFS shares.

The :mod:`manila.share.drivers.hpe.alletra_mp_b10000.hpe_alletra_driver` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.hpe.alletra_mp_b10000.hpe_alletra_driver
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:
