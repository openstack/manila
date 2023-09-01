=========================
Dell EMC PowerFlex driver
=========================

The Dell EMC Shared File Systems service driver framework (EMCShareDriver)
utilizes the Dell EMC storage products to provide the shared file systems to
OpenStack. The Dell EMC driver is a plug-in based driver which is designed to
use different plug-ins to manage different Dell EMC storage products.

The PowerFlex SDNAS plug-in manages the PowerFlex system to provide shared filesystems.
The Dell EMC driver framework with the PowerFlex SDNAS plug-in is referred to as the
PowerFlex SDNAS driver in this document.

The PowerFlex SDNAS driver can be used to provide functions such as share and
snapshot for instances.

The PowerFlex SDNAS driver enables the PowerFlex 4.x storage system to provide
file system management through REST API operations to OpenStack.


Requirements
------------

- PowerFlex 4.x storage system
- SDNAS cluster registrated with SDNAS Gateway.


Supported shared filesystems and operations
-------------------------------------------

The driver suppors NFS shares only.

The following operations are supported:

* Create a share.
* Delete a share.
* Allow share access.
* Deny share access.
* Extend a share.
* Create a snapshot.
* Delete a snapshot.


Driver configuration
--------------------

Edit the ``manila.conf`` file, which is usually located under the following
path ``/etc/manila/manila.conf``.

* Add a section for the PowerFlex SDNAS driver backend.

* Under the ``[DEFAULT]`` section, set the ``enabled_share_backends`` parameter
  with the name of the new backend section.

* Configure the driver backend section with the parameters below.

  .. code-block:: ini

      share_driver = manila.share.drivers.dell_emc.driver.EMCShareDriver
      emc_share_backend = powerflex
      dell_nas_backend_host = <Management IP of the PowerFlex system>
      dell_nas_backend_port = <Port number used for secured connection>
      dell_nas_server = <Name of the NAS server within the PowerFlex system>
      dell_nas_login = <user with administrator privilege>
      dell_nas_password = <password>
      powerflex_storage_pool = <Name of the storage pool>
      powerflex_protection_domain = <Name of the protection domain>
      share_backend_name = powerflex
      dell_ssl_cert_verify = <True|False>
      dell_ssl_certificate_path = <Path to SSL certificates>

  Where:

  +---------------------------------+----------------------------------------------------+
  | **Parameter**                   | **Description**                                    |
  +=================================+====================================================+
  | ``share_driver``                | Full path of the EMCShareDriver used to enable     |
  |                                 | the plugin.                                        |
  +---------------------------------+----------------------------------------------------+
  | ``emc_share_backend``           | The plugin name. Set it to `powerflex` to          |
  |                                 | enable the PowerFlex SDNAS driver.                 |
  +---------------------------------+----------------------------------------------------+
  | ``dell_nas_backend_host``       | The management IP of the PowerFlex system.         |
  +---------------------------------+----------------------------------------------------+
  | ``dell_nas_backend_port``       | The port number used for secured connection.       |
  |                                 | 443 by default if not provided.                    |
  +---------------------------------+----------------------------------------------------+
  | ``dell_nas_server``             | The name of the NAS server within the              |
  |                                 | PowerFlex system.                                  |
  +---------------------------------+----------------------------------------------------+
  | ``dell_nas_login``              | The login to use to connect to the PowerFlex       |
  |                                 | system. It must have administrator privileges.     |
  +---------------------------------+----------------------------------------------------+
  | ``dell_nas_password``           | The password associated with the login.            |
  +---------------------------------+----------------------------------------------------+
  | ``powerflex_storage_pool``      | The name of the storage pool within the            |
  |                                 | PowerFlex system.                                  |
  +---------------------------------+----------------------------------------------------+
  | ``powerflex_protection_domain`` | The name of the protection domain within the       |
  |                                 | PowerFlex system.                                  |
  +---------------------------------+----------------------------------------------------+
  | ``share_backend_name``          | The name of the backend which provides shares.     |
  |                                 | Must be set to powerflex                           |
  +---------------------------------+----------------------------------------------------+
  | ``dell_ssl_cert_verify``        | Boolean to enable the usage of SSL certificates.   |
  |                                 | False is the default value.                        |
  +---------------------------------+----------------------------------------------------+
  | ``dell_ssl_certificate_path``   | Full path to SSL certificates.                     |
  |                                 | Applies only when the usage of SSL certificate is  |
  |                                 | enabled.                                           |
  +---------------------------------+----------------------------------------------------+

Restart of manila-share service is needed for the configuration
changes to take effect.

Required operations prior to any usage
--------------------------------------

A new share type needs to be created before going further.

.. code-block:: console

    $ openstack share type create powerflex False

Map this share type to the backend section configured in Manila

.. code-block:: console

    $ openstack share type set --extra_specs share_backend_name=powerflex powerflex


Specific configuration for Snapshot support
-------------------------------------------

The following extra specifications need to be configured with share type.

- snapshot_support = True

For new share type, these extra specifications can be set directly when
creating share type:

.. code-block:: console

    $ openstack share type create --extra_specs snapshot_support=True powerflex False

Or you can update already existing share type with command:

.. code-block:: console

    $ openstack share type set --extra_specs snapshot_support=True powerflex


Known restrictions
------------------

The PowerFlex SDNAS driver has the following restrictions.

- Minimum size 3GiB.
- Only NFS protocol is supported.
- Only DHSS=False is supported
