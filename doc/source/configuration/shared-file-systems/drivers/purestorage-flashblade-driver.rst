==============================
Pure Storage FlashBlade driver
==============================

The Pure Storage FlashBlade driver provides support for managing filesystem shares
on the Pure Storage FlashBlade storage systems.

The driver is compatible with Pure Storage FlashBlades that support REST API version
1.6 or higher (Purity//FB v2.3.0 or higher).
This section explains how to configure the FlashBlade driver.

Supported operations
~~~~~~~~~~~~~~~~~~~~

- Create and delete NFS shares.

- Extend/Shrink a share.

- Create and delete filesystem snapshots (No support for create-from or mount).

- Revert to Snapshot.

- Both RW and RO access levels are supported.

- Set access rights to NFS shares.

  Note the following limitations:

  - Only IP (for NFS shares) access types are supported.

External package installation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The driver requires the ``purity_fb`` package for communicating with
FlashBlade systems. Install the package from PyPI using the following command:

.. code-block:: console

   $ pip install purity_fb

Driver configuration
~~~~~~~~~~~~~~~~~~~~

Edit the ``manila.conf`` file, which is usually located under the following
path ``/etc/manila/manila.conf``.

* Add a section for the FlashBlade driver back end.

* Under the ``[DEFAULT]`` section, set the ``enabled_share_backends`` parameter
  with the name of the new back-end section.

Configure the driver back-end section with the parameters below.

* Configure the driver name by setting the following parameter:

  .. code-block:: ini

     share_driver = manila.share.drivers.purestorage.flashblade.FlashBladeShareDriver

* Configure the management and data VIPs of the FlashBlade array by adding the
  following parameters:

  .. code-block:: ini

     flashblade_mgmt_vip = FlashBlade management VIP
     flashblade_data_vip = FlashBlade data VIP

* Configure user credentials:

  The driver requires a FlashBlade user with administrative privileges.
  We recommend creating a dedicated OpenStack user account
  that holds an administrative user role.
  Refer to the FlashBlade manuals for details on user account management.
  Configure the user credentials by adding the following parameters:

  .. code-block:: ini

     flashblade_api = FlashBlade API token for admin-privileged user

* (Optional) Configure File System and Snapshot Eradication:

  The option, when enabled, all FlashBlade file systems and snapshots will
  be eradicated at the time of deletion in Manila. Data will NOT be
  recoverable after a delete with this set to True! When disabled,
  file systems and snapshots will go into pending eradication state
  and can be recovered. Recovery of these pending eradication snapshots
  cannot be accomplished through Manila. These snapshots will self-eradicate
  after 24 hours unless manually restored. The default setting is True.

  .. code-block:: ini

     flashblade_eradicate = { True | False }

* The back-end name is an identifier for the back end.
  We recommend using the same name as the name of the section.
  Configure the back-end name by adding the following parameter:

  .. code-block:: ini

     share_backend_name = back-end name

Configuration example
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: ini

   [DEFAULT]
   enabled_share_backends = flashblade-1

   [flashblade-1]
   share_driver = manila.share.drivers.purestorage.flashblade.FlashBladeShareDriver
   share_backend_name = flashblade-1
   driver_handles_share_servers = false
   flashblade_mgmt_vip = 10.1.2.3
   flashblade_data_vip = 10.1.2.4
   flashblade_api = pureuser API

Driver options
~~~~~~~~~~~~~~

Configuration options specific to this driver:

.. include:: ../../tables/manila-purestorage-flashblade.inc
