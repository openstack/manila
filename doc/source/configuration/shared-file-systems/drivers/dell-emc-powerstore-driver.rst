===========================
Dell EMC PowerStore Plugin
===========================

The Dell EMC Shared File Systems service driver framework (EMCShareDriver)
utilizes the Dell EMC storage products to provide the shared file systems
to OpenStack. The Dell EMC driver is a plug-in based driver which is designed
to use different plug-ins to manage different Dell EMC storage products.

The PowerStore plug-in manages the PowerStore to provide shared file systems.
The Dell EMC driver framework with the PowerStore plug-in is referred to as the
PowerStore driver in this document.

This driver performs the operations on PowerStore through RESTful APIs. Each backend
manages one PowerStore storage system. Configure multiple Shared File Systems service
backends to manage multiple PowerStore systems.


Requirements
------------

- PowerStore version 3.0 or higher.
- PowerStore File is enabled.


Supported shared filesystems and operations
-------------------------------------------

The driver supports NFS shares and CIFS shares.

The following operations are supported.

-  Create a share.
-  Delete a share.
-  Allow share access.
-  Deny share access.
-  Extend a share.
-  Shrink a share.
-  Create a snapshot.
-  Delete a snapshot.
-  Create a share from a snapshot.
-  Revert a share to a snapshot.
-  Manage/Unmanage a share.
-  Manage/Unmanage a snapshot.


Driver configuration
--------------------

Edit the configuration file ``/etc/manila/manila.conf``.

* Add a section for the PowerStore driver backend.

* Under the ``[DEFAULT]`` section, set the ``enabled_share_backends`` parameter
  with the name of the new backend section.

* Configure the driver backend section with the parameters below.

  .. code-block:: ini

      share_driver = manila.share.drivers.dell_emc.driver.EMCShareDriver
      emc_share_backend = powerstore
      dell_nas_backend_host = <Management IP of the PowerStore system>
      dell_nas_server = <Name of the NAS server in the PowerStore system>
      dell_ad_domain = <Domain name of the active directory joined by the NAS server>
      dell_nas_login = <User with administrator privilege>
      dell_nas_password = <Password>
      share_backend_name = <Backend name>
      dell_ssl_cert_verify = True/False
      dell_ssl_cert_path = <Path to cert>

  Where:

  +---------------------------------+----------------------------------------------------+
  | **Parameter**                   | **Description**                                    |
  +=================================+====================================================+
  | ``share_driver``                | Full path of the EMCShareDriver used to enable     |
  |                                 | the plugin.                                        |
  +---------------------------------+----------------------------------------------------+
  | ``emc_share_backend``           | The plugin name. Set it to `powerstore` to         |
  |                                 | enable the PowerStore driver.                      |
  +---------------------------------+----------------------------------------------------+
  | ``dell_nas_backend_host``       | The management IP of the PowerStore system.        |
  +---------------------------------+----------------------------------------------------+
  | ``dell_nas_server``             | The name of the NAS server in the                  |
  |                                 | PowerStore system.                                 |
  +---------------------------------+----------------------------------------------------+
  | ``dell_ad_domain``              | The name of the Active Directory Domain.           |
  |                                 | Only applicable when the SMB server joins          |
  |                                 | to the Active Directory Domain.                    |
  +---------------------------------+----------------------------------------------------+
  | ``dell_nas_login``              | The login to use to connect to the PowerStore      |
  |                                 | system. It must have administrator privileges.     |
  +---------------------------------+----------------------------------------------------+
  | ``dell_nas_password``           | The password associated with the login.            |
  +---------------------------------+----------------------------------------------------+
  | ``share_backend_name``          | The share backend name for a given driver          |
  |                                 | implementation.                                    |
  +---------------------------------+----------------------------------------------------+
  | ``dell_ssl_cert_verify``        | The https client validates the SSL certificate of  |
  |                                 | the PowerStore endpoint. Optional.                 |
  |                                 | Value: True or False.                              |
  |                                 | Default: False.                                    |
  +---------------------------------+----------------------------------------------------+
  | ``dell_ssl_cert_path``          | The path to PowerStore SSL certificate on          |
  |                                 | Manila host. Optional.                             |
  +---------------------------------+----------------------------------------------------+

Restart of ``manila-share`` service is needed for the configuration
changes to take effect.


Pre-configurations for share support (DHSS=False)
--------------------------------------------------

To create a file share in this mode, you need to:

#. Create NAS server with network interface in PowerStore system.
#. Set 'dell_nas_server' in ``/etc/manila/manila.conf``:

    .. code-block:: ini

        dell_nas_server = <name of NAS server in PowerStore system>

#. Create the share type with driver_handles_share_servers = False extra
   specification:

    .. code-block:: console

        $ openstack share type create ${share_type_name} False

#. Map this share type to the share backend name

    .. code-block:: console

        $ openstack share type set ${share_type_name} \
            --extra-specs share_backend_name=${share_backend_name}

#. Create NFS share.

    .. code-block:: console

        $ openstack share create NFS ${size} --name ${share_name} --share-type ${share_type_name}


Pre-configurations for snapshot support
---------------------------------------

The driver can:
- create/delete a snapshot
- create a share from a snapshot
- revert a share to a snapshot

The following extra specifications need to be configured with share type.

- snapshot_support = True
- create_share_from_snapshot_support = True
- revert_to_snapshot_support = True

For new share type, these extra specifications can be set directly when
creating share type:

    .. code-block:: console

        $ openstack share type create ${share_type_name} False \
            --snapshot-support=True \
            --create-share-from-snapshot-support=True \
            --revert-to-snapshot-support=True

Or you can update already existing share type with command:

    .. code-block:: console

        $ openstack share type set ${share_type_name} \
            --extra-specs snapshot_support=True \
                create_share_from_snapshot_support=True \
                revert_to_snapshot_support=True


Manage and unmanage shares
--------------------------

The driver supports the manage (adopt) and unmanage (abandon) operations
for existing NFS and CIFS shares on a PowerStore backend.

Managing and unmanaging existing shares is performed using the OpenStack
dashboard or CLI.

For detailed usage instructions, refer to the Manila administration
documentation:

:doc:`/admin/shared-file-systems-manage-and-unmanage-share`

.. note::

   * Unmanage does not delete the share on the backend; existing clients
     remain connected.

QoS support
-----------

The PowerStore driver supports QoS (Quality of Service) to enforce bandwidth
limits on file shares. This feature requires PowerStore API version 4.1.0.0
or later.

The driver uses Manila's QoS type framework. The supported QoS spec is:

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - **Spec Key**
     - **Description**
   * - ``max_bw``
     - Maximum bandwidth in MB/s. Integer value from 1 to 1000000.

To use QoS with PowerStore shares:

#. Create a QoS type:

    .. code-block:: console

        $ openstack share qos type create powerstore_qos max_bw:500

#. Associate the QoS type with a share type via the ``default_qos_type``
   extra-spec:

    .. code-block:: console

        $ openstack share type set ${share_type_name} \
            --extra-specs default_qos_type=powerstore_qos

#. Create a share using that share type. The driver will automatically
   create a file I/O limit rule and performance policy on the PowerStore
   array and apply it to the filesystem.

When a share is deleted, the driver cleans up the associated performance
policy and I/O limit rule if no other filesystems reference them.

Updating QoS type specs
^^^^^^^^^^^^^^^^^^^^^^^^

If an administrator updates the QoS type specs (e.g., changes ``max_bw``
from 500 to 1000), the updated values are applied on the PowerStore array
the next time a share is created with that QoS type. Because all shares
with the same QoS type share a single file I/O limit rule on the array,
the update takes effect for all existing shares as well.

.. note::

   The update is not applied immediately when the QoS type spec is
   modified. It is applied when the next share using that QoS type is
   created. This is consistent with the behavior of other Manila drivers.


Manage and unmanage snapshots
-----------------------------

The driver supports the manage (adopt) and unmanage (abandon) operations
for existing snapshots of NFS and CIFS shares on a PowerStore backend.

Managing and unmanaging existing snapshots is performed using the OpenStack
dashboard or CLI.

For detailed usage instructions, refer to the Manila administration
documentation:

:doc:`/admin/shared-file-systems-manage-and-unmanage-snapshot`

.. note::

   * Unmanage does not delete the snapshot on the backend.
   * Only snapshots that belong to a share already managed by Manila
     can be managed.


Known restrictions
------------------

The PowerStore driver has the following restrictions.

- Minimum share size is 3GiB.
- Only IP access type is supported for NFS shares.
- Only user access type is supported for CIFS shares.
- Only DHSS=False is supported.
- Modification of CIFS share access is supported in PowerStore 3.5 and above.
- QoS support requires PowerStore API version 4.1.0.0 or later.
