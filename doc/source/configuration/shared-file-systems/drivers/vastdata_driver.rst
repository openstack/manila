====================================
Vastdata Share Driver
====================================

VAST Share Driver integrates OpenStack with
`VAST Data <https://www.vastdata.com>`__'s Storage System.
Shares in the Shared File System service
are mapped to directories on VAST,
and are accessed via NFS protocol using a Virtual IP Pool.

Supported shared filesystems
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The driver supports NFS shares.

Operations supported
~~~~~~~~~~~~~~~~~~~~
The driver supports NFS shares.

The following operations are supported:

-  Create a share.

-  Delete a share.

-  Allow share access.

- Deny share access.

- Extend a share.

- Shrink a share.


Requirements
~~~~~~~~~~~~

- The Trash Folder Access functionality must be enabled on the VAST cluster.

Driver options
~~~~~~~~~~~~~~

The following table contains the configuration options specific to the
share driver.

.. include:: ../../tables/manila-vastdata.inc


VAST Share Driver configuration example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following example shows parameters in the ``manila.conf`` file
that are used to configure VAST Share Driver.
They include two options under ``[DEFAULT]`` and parameters under ``[vast]``.
Note that a real ``manila.conf`` file would also include
other parameters that are not specific to VAST Share Driver.

.. code-block:: ini

   [DEFAULT]
   enabled_share_backends = vast
   enabled_share_protocols = NFS

   [vast]
   share_driver = manila.share.drivers.vastdata.driver.VASTShareDriver
   share_backend_name = vast
   driver_handles_share_servers = False
   snapshot_support = True
   vast_mgmt_host = {vms_ip}
   vast_mgmt_port = {vms_port}
   vast_mgmt_user = {mgmt_user}
   vast_mgmt_password = {mgmt_password}
   vast_vippool_name = {vip_pool}
   vast_root_export = {root_export}


Restart of the ``manila-share`` service is needed for the configuration
changes to take effect.


Pre-configurations for share support
--------------------------------------------------

To create a file share, you need to:

Create the share type:

.. code-block:: console

    openstack share type create ${share_type_name} False \
        --extra-specs share_backend_name=${share_backend_name}

Create an NFS share:

.. code-block:: console

    openstack share create NFS ${size} --name ${share_name} --share-type ${share_type_name}

Pre-Configurations for Snapshot support
--------------------------------------------------

The share type must have the following parameter specified:

- snapshot_support = True

You can specify it when creating a new share type:

.. code-block:: console

    openstack share type create ${share_type_name} false \
        --snapshot-support=true \
        --extra-specs share_backend_name=${share_backend_name}

Or you can add it to an existing share type:

.. code-block:: console

    openstack share type set ${share_type_name} --extra-specs snapshot_support=True


To snapshot a share and create share from the snapshot
------------------------------------------------------

Create a share using a share type with snapshot_support=True.
Then, create a snapshot of the share using the command:

.. code-block:: console

    openstack share snapshot create ${source_share_name} --name ${target_snapshot_name}


The :mod:`manila.share.drivers.vastdata.driver` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.vastdata.driver
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:
