Creating shares with Shared File Systems Option 2 (DHSS = True)
---------------------------------------------------------------

Before being able to create a share, manila with the generic driver and
the DHSS (``driver_handles_share_servers``) mode enabled requires the
definition of at least an image, a network and a share-network for being
used to create a share server. For that `back end` configuration, the share
server is an instance where NFS shares are served.

.. note::

   This configuration automatically creates a cinder volume for every share.
   The cinder volumes are attached to share servers according to the
   definition of a share network.


#. Source the admin credentials to gain access to admin-only CLI commands:

   .. code-block:: console

      $ . admin-openrc.sh

#. Create a default share type with DHSS enabled. A default share type will
   allow you to create shares with this driver, without having to specify
   the share type explicitly during share creation.

   .. code-block:: console

      $ manila type-create default_share_type True
      +----------------------+--------------------------------------+
      | Property             | Value                                |
      +----------------------+--------------------------------------+
      | required_extra_specs | driver_handles_share_servers : True  |
      | Name                 | default_share_type                   |
      | Visibility           | public                               |
      | is_default           | -                                    |
      | ID                   | 8a35da28-0f74-490d-afff-23664ecd4f01 |
      | optional_extra_specs | snapshot_support : True              |
      +----------------------+--------------------------------------+

   Set this default share type in ``manila.conf`` under the ``[DEFAULT]``
   section and restart the ``manila-api`` service before proceeding.
   Unless you do so, the default share type will not be effective.

   .. note::

      Creating and configuring a default share type is optional. If you wish
      to use the shared file system service with a variety of share types,
      where each share creation request could specify a type, please refer to
      the Share types usage documentation `here
      <https://docs.openstack.org/manila/latest/admin/shared-file-systems-share-types.html>`_.

#. Create a manila share server image in the Image service. You may skip this
   step and use any existing image. However, for mounting a share, the service
   image must contain the NFS packages as appropriate for the operating system.
   Whatever image you choose to be the service image, be sure to set the
   configuration values ``service_image_name``, ``service_instance_flavor_id``,
   ``service_instance_user`` and ``service_instance_password`` in
   ``manila.conf``.

   .. note::

      Any changes made to ``manila.conf`` while the ``manila-share`` service
      is running will require a restart of the service to be effective.

   .. note::

      As an alternative to specifying a plain-text
      ``service_instance_password`` in your configuration, a key-pair may be
      specified with options ``path_to_public_key`` and
      ``path_to_private_key`` to configure and allow password-less SSH access
      between the `share node` and the share server/s created.

   .. code-block:: console

      $ glance image-create \
      --copy-from http://tarballs.openstack.org/manila-image-elements/images/manila-service-image-master.qcow2 \
      --name "manila-service-image" \
      --disk-format qcow2 \
      --container-format bare \
      --visibility public --progress
      [=============================>] 100%
      +------------------+--------------------------------------+
      | Property         | Value                                |
      +------------------+--------------------------------------+
      | checksum         | 48a08e746cf0986e2bc32040a9183445     |
      | container_format | bare                                 |
      | created_at       | 2016-01-26T19:52:24Z                 |
      | disk_format      | qcow2                                |
      | id               | 1fc7f29e-8fe6-44ef-9c3c-15217e83997c |
      | min_disk         | 0                                    |
      | min_ram          | 0                                    |
      | name             | manila-service-image                 |
      | owner            | e2c965830ecc4162a002bf16ddc91ab7     |
      | protected        | False                                |
      | size             | 306577408                            |
      | status           | active                               |
      | tags             | []                                   |
      | updated_at       | 2016-01-26T19:52:28Z                 |
      | virtual_size     | None                                 |
      | visibility       | public                               |
      +------------------+--------------------------------------+

#. List available networks in order to get id and subnets of the private
   network:

   .. code-block:: console

      $ neutron net-list
      +--------------------------------------+---------+----------------------------------------------------+
      | id                                   | name    | subnets                                            |
      +--------------------------------------+---------+----------------------------------------------------+
      | 0e62efcd-8cee-46c7-b163-d8df05c3c5ad | public  | 5cc70da8-4ee7-4565-be53-b9c011fca011 10.3.31.0/24  |
      | 7c6f9b37-76b4-463e-98d8-27e5686ed083 | private | 3482f524-8bff-4871-80d4-5774c2730728 172.16.1.0/24 |
      +--------------------------------------+---------+----------------------------------------------------+

#. Source the ``demo`` credentials to perform
   the following steps as a non-administrative project:

   .. code-block:: console

      $ . demo-openrc.sh

   .. code-block:: console

      $ manila share-network-create --name demo-share-network1 \
      --neutron-net-id PRIVATE_NETWORK_ID \
      --neutron-subnet-id PRIVATE_NETWORK_SUBNET_ID
      +-------------------+--------------------------------------+
      | Property          | Value                                |
      +-------------------+--------------------------------------+
      | name              | demo-share-network1                  |
      | segmentation_id   | None                                 |
      | created_at        | 2016-01-26T20:03:41.877838           |
      | neutron_subnet_id | 3482f524-8bff-4871-80d4-5774c2730728 |
      | updated_at        | None                                 |
      | network_type      | None                                 |
      | neutron_net_id    | 7c6f9b37-76b4-463e-98d8-27e5686ed083 |
      | ip_version        | None                                 |
      | cidr              | None                                 |
      | project_id        | e2c965830ecc4162a002bf16ddc91ab7     |
      | id                | 58b2f0e6-5509-4830-af9c-97f525a31b14 |
      | description       | None                                 |
      +-------------------+--------------------------------------+

Create a share
--------------

#. Create an NFS share using the share network. Since a default share type has
   been created and configured, it need not be specified in the request.

   .. code-block:: console

      $ manila create NFS 1 --name demo-share1 --share-network demo-share-network1
      +-----------------------------+--------------------------------------+
      | Property                    | Value                                |
      +-----------------------------+--------------------------------------+
      | status                      | None                                 |
      | share_type_name             | default_share_type                   |
      | description                 | None                                 |
      | availability_zone           | None                                 |
      | share_network_id            | 58b2f0e6-5509-4830-af9c-97f525a31b14 |
      | share_group_id              | None                                 |
      | host                        | None                                 |
      | snapshot_id                 | None                                 |
      | is_public                   | False                                |
      | task_state                  | None                                 |
      | snapshot_support            | True                                 |
      | id                          | 016ca18f-bdd5-48e1-88c0-782e4c1aa28c |
      | size                        | 1                                    |
      | name                        | demo-share1                          |
      | share_type                  | 8a35da28-0f74-490d-afff-23664ecd4f01 |
      | created_at                  | 2016-01-26T20:08:50.502877           |
      | export_location             | None                                 |
      | share_proto                 | NFS                                  |
      | project_id                  | 48e8c35b2ac6495d86d4be61658975e7     |
      | metadata                    | {}                                   |
      +-----------------------------+--------------------------------------+

#. After some time, the share status should change from ``creating``
   to ``available``:

   .. code-block:: console

      $ manila list
      +--------------------------------------+-------------+------+-------------+-----------+-----------+------------------------+-----------------------------+-------------------+
      | ID                                   | Name        | Size | Share Proto | Status    | Is Public | Share Type Name        | Host                        | Availability Zone |
      +--------------------------------------+-------------+------+-------------+-----------+-----------+------------------------+-----------------------------+-------------------+
      | 5f8a0574-a95e-40ff-b898-09fd8d6a1fac | demo-share1 | 1    | NFS         | available | False     |   default_share_type   | storagenode@generic#GENERIC | nova              |
      +--------------------------------------+-------------+------+-------------+-----------+-----------+------------------------+-----------------------------+-------------------+

#. Determine export IP address of the share:

   .. code-block:: console

      $ manila show demo-share1
      +-----------------------------+------------------------------------------------------------------------------------+
      | Property                    | Value                                                                              |
      +-----------------------------+------------------------------------------------------------------------------------+
      | status                      | available                                                                          |
      | share_type_name             | default_share_type                                                                 |
      | description                 | None                                                                               |
      | availability_zone           | nova                                                                               |
      | share_network_id            | 58b2f0e6-5509-4830-af9c-97f525a31b14                                               |
      | share_group_id              | None                                                                               |
      | export_locations            |                                                                                    |
      |                             | path = 10.254.0.6:/shares/share-0bfd69a1-27f0-4ef5-af17-7cd50bce6550               |
      |                             | id = e525cbca-b3cc-4adf-a1cb-b1bf48fa2422                                          |
      |                             | preferred = False                                                                  |
      | host                        | storagenode@generic#GENERIC                                                        |
      | access_rules_status         | active                                                                             |
      | snapshot_id                 | None                                                                               |
      | is_public                   | False                                                                              |
      | task_state                  | None                                                                               |
      | snapshot_support            | True                                                                               |
      | id                          | 5f8a0574-a95e-40ff-b898-09fd8d6a1fac                                               |
      | size                        | 1                                                                                  |
      | name                        | demo-share1                                                                        |
      | share_type                  | 8a35da28-0f74-490d-afff-23664ecd4f01                                               |
      | has_replicas                | False                                                                              |
      | replication_type            | None                                                                               |
      | created_at                  | 2016-03-30T19:10:33.000000                                                         |
      | share_proto                 | NFS                                                                                |
      | project_id                  | 48e8c35b2ac6495d86d4be61658975e7                                                   |
      | metadata                    | {}                                                                                 |
      +-----------------------------+------------------------------------------------------------------------------------+

Allow access to the share
-------------------------

#. Configure access to the new share before attempting to mount it via
   the network. The compute instance (whose IP address is referenced by the
   INSTANCE_IP below) must have network connectivity to the network specified
   in the share network.

   .. code-block:: console

      $ manila access-allow demo-share1 ip INSTANCE_IP
      +--------------+--------------------------------------+
      | Property     | Value                                |
      +--------------+--------------------------------------+
      | share_id     | 5f8a0574-a95e-40ff-b898-09fd8d6a1fac |
      | access_type  | ip                                   |
      | access_to    | 10.0.0.46                            |
      | access_level | rw                                   |
      | state        | new                                  |
      | id           | aefeab01-7197-44bf-ad0f-d6ca6f99fc96 |
      +--------------+--------------------------------------+


Mount the share on a compute instance
-------------------------------------

#. Log into your compute instance and create a folder where the mount will
   be placed:

   .. code-block:: console

      $ mkdir ~/test_folder

#. Mount the NFS share in the compute instance using the export location of
   the share:

   .. code-block:: console

      $ mount -vt nfs 10.254.0.6:/shares/share-0bfd69a1-27f0-4ef5-af17-7cd50bce6550 ~/test_folder
