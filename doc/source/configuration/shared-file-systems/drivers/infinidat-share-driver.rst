================================
INFINIDAT InfiniBox Share driver
================================

The INFINIDAT Share driver provides support for managing filesystem shares
on the INFINIDAT InfiniBox storage systems.

This section explains how to configure the INFINIDAT driver.

Supported operations
~~~~~~~~~~~~~~~~~~~~

- Create and delete filesystem shares.

- Ensure filesystem shares.

- Extend a share.

- Create and delete filesystem snapshots.

- Create a share from a share snapshot.

- Revert a share to its snapshot.

- Mount a snapshot.

- Set access rights to shares and snapshots.

  Note the following limitations:

  - Only IP access type is supported.

  - Both RW & RO access levels are supported.

External package installation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The driver requires the ``infinisdk`` package for communicating with
InfiniBox systems. Install the package from PyPI using the following command:

.. code-block:: console

   $ pip install infinisdk

Setting up the storage array
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Create a storage pool object on the InfiniBox array in advance.
The storage pool will contain shares managed by OpenStack.
Refer to the InfiniBox manuals for details on pool management.

Driver configuration
~~~~~~~~~~~~~~~~~~~~

Edit the ``manila.conf`` file, which is usually located under the following
path ``/etc/manila/manila.conf``.

* Add a section for the INFINIDAT driver back end.

* Under the ``[DEFAULT]`` section, set the ``enabled_share_backends`` parameter
  with the name of the new back-end section.

Configure the driver back-end section with the parameters below.

* Configure the driver name by setting the following parameter:

  .. code-block:: ini

     share_driver = manila.share.drivers.infinidat.infinibox.InfiniboxShareDriver

* Configure the management IP of the InfiniBox array by adding the following
  parameter:

  .. code-block:: ini

     infinibox_hostname = InfiniBox management IP

* Configure user credentials:

  The driver requires an InfiniBox user with administrative privileges.
  We recommend creating a dedicated OpenStack user account
  that holds an administrative user role.
  Refer to the InfiniBox manuals for details on user account management.
  Configure the user credentials by adding the following parameters:

  .. code-block:: ini

     infinibox_login = Infinibox management login
     infinibox_password = Infinibox management password

* Configure the name of the InfiniBox pool by adding the following parameter:

  .. code-block:: ini

     infinidat_pool_name = Pool as defined in the InfiniBox

* Configure the name of the InfiniBox NAS network space by adding the following
  parameter:

  .. code-block:: ini

     infinidat_nas_network_space_name = Network space as defined in the InfiniBox

* The back-end name is an identifier for the back end.
  We recommend using the same name as the name of the section.
  Configure the back-end name by adding the following parameter:

  .. code-block:: ini

     share_backend_name = back-end name

* Thin provisioning:

  The INFINIDAT driver supports creating thin or thick provisioned filesystems.
  Configure thin or thick provisioning by adding the following parameter:

  .. code-block:: ini

     infinidat_thin_provision = true/false

  This parameter defaults to ``true``.

Configuration example
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: ini

   [DEFAULT]
   enabled_share_backends = infinidat-pool-a

   [infinidat-pool-a]
   share_driver = manila.share.drivers.infinidat.infinibox.InfiniboxShareDriver
   share_backend_name = infinidat-pool-a
   driver_handles_share_servers = false
   infinibox_hostname = 10.1.2.3
   infinibox_login = openstackuser
   infinibox_password = openstackpass
   infinidat_pool_name = pool-a
   infinidat_nas_network_space_name = nas_space
   infinidat_thin_provision = true

Driver options
~~~~~~~~~~~~~~

Configuration options specific to this driver:

.. include:: ../../tables/manila-infinidat.inc
