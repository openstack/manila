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

      $ openstack share type create default_share_type True
      +----------------------+--------------------------------------+
      | Field                | Value                                |
      +----------------------+--------------------------------------+
      | id                   | 0c5e5365-e3b3-4c4d-8a10-5e1a0b204467 |
      | name                 | default_share_type                   |
      | visibility           | public                               |
      | is_default           | -                                    |
      | required_extra_specs | driver_handles_share_servers : True  |
      | optional_extra_specs | snapshot_support : True              |
      | description          | None                                 |
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

      $ curl -L \
      https://tarballs.opendev.org/openstack/manila-image-elements/images/manila-service-image-master.qcow2 \
      -o /tmp/manila-service-image.qcow2
      $ openstack image create "manila-service-image" \
      --file /tmp/manila-service-image.qcow2 \
      --disk-format qcow2 \
      --container-format bare \
      --public
      +------------------+--------------------------------------+
      | Field            | Value                                |
      +------------------+--------------------------------------+
      | container_format | bare                                 |
      | created_at       | 2026-03-31T19:52:24Z                 |
      | disk_format      | qcow2                                |
      | id               | 1fc7f29e-8fe6-44ef-9c3c-15217e83997c |
      | min_disk         | 0                                    |
      | min_ram          | 0                                    |
      | name             | manila-service-image                 |
      | owner            | e2c965830ecc4162a002bf16ddc91ab7     |
      | protected        | False                                |
      | size             | 306577408                            |
      | status           | active                               |
      | tags             |                                      |
      | updated_at       | 2026-03-31T19:52:28Z                 |
      | visibility       | public                               |
      +------------------+--------------------------------------+

#. List available networks in order to get id and subnets of the private
   network:

   .. code-block:: console

      $ openstack network list
      +--------------------------------------+---------+--------------------------------------+
      | ID                                   | Name    | Subnets                              |
      +--------------------------------------+---------+--------------------------------------+
      | 0e62efcd-8cee-46c7-b163-d8df05c3c5ad | public  | 5cc70da8-4ee7-4565-be53-b9c011fca011 |
      | 7c6f9b37-76b4-463e-98d8-27e5686ed083 | private | 3482f524-8bff-4871-80d4-5774c2730728 |
      +--------------------------------------+---------+--------------------------------------+

#. Source the ``demo`` credentials to perform
   the following steps as a non-administrative project:

   .. code-block:: console

      $ . demo-openrc.sh

   .. code-block:: console

      $ openstack share network create --name demo-share-network1 \
          --neutron-net-id PRIVATE_NETWORK_ID \
          --neutron-subnet-id PRIVATE_NETWORK_SUBNET_ID
      +-----------------------------------+----------------------------------------------------------+
      | Field                             | Value                                                    |
      +-----------------------------------+----------------------------------------------------------+
      | id                                | 58b2f0e6-5509-4830-af9c-97f525a31b14                     |
      | name                              | demo-share-network1                                      |
      | project_id                        | e2c965830ecc4162a002bf16ddc91ab7                         |
      | created_at                        | 2026-03-31T20:03:41.877838                               |
      | updated_at                        | None                                                     |
      | description                       | None                                                     |
      | status                            | active                                                   |
      | share_network_subnets             |                                                          |
      |                                   | id = d952ef97-e2f5-47b8-bf19-516b10d56782                |
      |                                   | availability_zone = None                                 |
      |                                   | created_at = 2026-03-31T20:03:41.905123                  |
      |                                   | segmentation_id = None                                   |
      |                                   | neutron_net_id = 7c6f9b37-76b4-463e-98d8-27e5686ed083    |
      |                                   | neutron_subnet_id = 3482f524-8bff-4871-80d4-5774c2730728 |
      |                                   | ip_version = None                                        |
      |                                   | cidr = None                                              |
      |                                   | network_type = None                                      |
      +-----------------------------------+----------------------------------------------------------+

Create a share
--------------

#. Create an NFS share using the share network. Since a default share type has
   been created and configured, it need not be specified in the request.

   .. code-block:: console

      $ openstack share create NFS 1 --name demo-share1 \
          --share-network demo-share-network1
      +---------------------------------------+--------------------------------------+
      | Field                                 | Value                                |
      +---------------------------------------+--------------------------------------+
      | id                                    | 80397c62-176c-474b-bd1f-af249caa9ec4 |
      | size                                  | 1                                    |
      | availability_zone                     | None                                 |
      | created_at                            | 2026-03-31T20:08:25.807322           |
      | status                                | creating                             |
      | name                                  | demo-share1                          |
      | description                           | None                                 |
      | project_id                            | 48e8c35b2ac6495d86d4be61658975e7     |
      | snapshot_id                           | None                                 |
      | share_network_id                      | 58b2f0e6-5509-4830-af9c-97f525a31b14 |
      | share_proto                           | NFS                                  |
      | metadata                              | {}                                   |
      | share_type                            | 0c5e5365-e3b3-4c4d-8a10-5e1a0b204467 |
      | is_public                             | False                                |
      | snapshot_support                      | True                                 |
      | task_state                            | None                                 |
      | share_type_name                       | default_share_type                   |
      | access_rules_status                   | active                               |
      | replication_type                      | None                                 |
      | has_replicas                          | False                                |
      | user_id                               | a6c6f585fe5249cbb91426b37e1161a7     |
      | create_share_from_snapshot_support    | True                                 |
      | revert_to_snapshot_support            | True                                 |
      | share_group_id                        | None                                 |
      | source_share_group_snapshot_member_id | None                                 |
      | mount_snapshot_support                | True                                 |
      | progress                              | None                                 |
      +---------------------------------------+--------------------------------------+

#. After some time, the share status should change from ``creating``
   to ``available``:

   .. code-block:: console

      $ openstack share list
      +--------------------------------------+-------------+------+-------------+-----------+-----------+--------------------+-----------------------------+-------------------+
      | ID                                   | Name        | Size | Share Proto | Status    | Is Public | Share Type Name    | Host                        | Availability Zone |
      +--------------------------------------+-------------+------+-------------+-----------+-----------+--------------------+-----------------------------+-------------------+
      | 80397c62-176c-474b-bd1f-af249caa9ec4 | demo-share1 |    1 | NFS         | available | False     | default_share_type | storagenode@generic#GENERIC | nova              |
      +--------------------------------------+-------------+------+-------------+-----------+-----------+--------------------+-----------------------------+-------------------+

#. Determine export IP address of the share:

   .. code-block:: console

      $ openstack share show demo-share1
      +---------------------------------------+----------------------------------------------------------------------+
      | Field                                 | Value                                                                |
      +---------------------------------------+----------------------------------------------------------------------+
      | id                                    | 80397c62-176c-474b-bd1f-af249caa9ec4                                 |
      | size                                  | 1                                                                    |
      | availability_zone                     | nova                                                                 |
      | created_at                            | 2026-03-31T20:08:25.807322                                           |
      | status                                | available                                                            |
      | name                                  | demo-share1                                                          |
      | description                           | None                                                                 |
      | project_id                            | 48e8c35b2ac6495d86d4be61658975e7                                     |
      | snapshot_id                           | None                                                                 |
      | share_network_id                      | 58b2f0e6-5509-4830-af9c-97f525a31b14                                 |
      | share_proto                           | NFS                                                                  |
      | share_type                            | 0c5e5365-e3b3-4c4d-8a10-5e1a0b204467                                 |
      | is_public                             | False                                                                |
      | snapshot_support                      | True                                                                 |
      | task_state                            | None                                                                 |
      | share_type_name                       | default_share_type                                                   |
      | access_rules_status                   | active                                                               |
      | replication_type                      | None                                                                 |
      | has_replicas                          | False                                                                |
      | user_id                               | a6c6f585fe5249cbb91426b37e1161a7                                     |
      | create_share_from_snapshot_support    | True                                                                 |
      | revert_to_snapshot_support            | True                                                                 |
      | share_group_id                        | None                                                                 |
      | source_share_group_snapshot_member_id | None                                                                 |
      | mount_snapshot_support                | True                                                                 |
      | progress                              | 100%                                                                 |
      | export_locations                      |                                                                      |
      |                                       | id = a329a0c1-ad55-4500-bd57-b17c0d1567e1                            |
      |                                       | path = 192.0.2.6:/shares/share-0bfd69a1-27f0-4ef5-af17-7cd50bce6550  |
      |                                       | preferred = True                                                     |
      | properties                            |                                                                      |
      +---------------------------------------+----------------------------------------------------------------------+

Allow access to the share
-------------------------

#. Configure access to the new share before attempting to mount it via
   the network. The compute instance (whose IP address is referenced by the
   INSTANCE_IP below) must have network connectivity to the network specified
   in the share network.

   .. code-block:: console

      $ openstack share access create demo-share1 ip INSTANCE_IP
      +--------------+--------------------------------------+
      | Field        | Value                                |
      +--------------+--------------------------------------+
      | id           | eb04dfed-aa25-4cea-99c0-4d0969909cd9 |
      | share_id     | 80397c62-176c-474b-bd1f-af249caa9ec4 |
      | access_level | rw                                   |
      | access_to    | 198.51.100.46                        |
      | access_type  | ip                                   |
      | state        | queued_to_apply                      |
      | access_key   | None                                 |
      | created_at   | 2026-03-31T20:09:05.198219           |
      | updated_at   | None                                 |
      | properties   |                                      |
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

      $ mount -vt nfs \
          192.0.2.6:/shares/share-0bfd69a1-27f0-4ef5-af17-7cd50bce6550 \
          ~/test_folder
