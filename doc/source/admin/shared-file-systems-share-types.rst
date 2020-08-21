.. _shared_file_systems_share_types:

===========
Share types
===========

The Shared File System service back-end storage drivers offer a wide range
of capabilities. The variation in these capabilities allows cloud
administrators to provide a storage service catalog to their end users.
Share types can be used to create this storage service catalog.
Cloud administrators can influence provisioning of users' shares with the
help of Share types. All shares are associated with a share type. Share
types are akin to ``flavors`` in the OpenStack Compute service (nova), or
``volume types`` in the OpenStack Block Storage service (cinder), or ``storage
classes`` in Kubernetes. You can allow a share type to be accessible to all
users in your cloud if you wish. You can also create private share types that
allow only users belonging to certain OpenStack projects to access them.
You can have an unlimited number of share types in your
cloud, but for practical purposes, you may want to create only a handful of
publicly accessible share types.

Each share type is an object that encompasses ``extra-specs`` (extra
specifications). These extra-specs can map to storage back-end capabilities,
or can be directives to the service.

Consider for example, offering three share types in your cloud to map
to "service levels":

+--------+--------------------------------------------------------------------------------------------------+
|  Type  |                                    Capabilities/Instructions                                     |
+========+==================================================================================================+
| Gold   | Allow creating snapshots, reverting to snapshots and share replication, "thick" provision shares |
+--------+--------------------------------------------------------------------------------------------------+
| Silver | Allow creating snapshots, "thin" provision shares                                                |
+--------+--------------------------------------------------------------------------------------------------+
| Bronze | Don't allow creating snapshots, "thin" provision shares                                          |
+--------+--------------------------------------------------------------------------------------------------+

Capabilities or instructions such as the ones above are coded as extra-specs
that your users and the Shared File System service understand. Users in
OpenStack projects can see all public share types along with private share
types that are made accessible to them. Not all extra-specs that you
configure in a share type are visible to your users. This design helps
preserve the cloud abstraction. Along with the share type names, they can
see the share type descriptions and "tenant-visible" extra-specs.

For more details on extra-specs, see :ref:`capabilities_and_extra_specs`.

The Shared File Systems service also allows using quota controls with share
types. Quotas can help you maintain your SLAs by limiting the number of
consumable resources or aid in billing. See :ref:`shared_file_systems_quotas`
for more details.

Driver Handles Share Servers (DHSS)
-----------------------------------

To provide secure and hard multi-tenancy on the network data path, the
Shared File Systems service allows users to use their own "share networks".
When shares are created on a share network, users can be sure they have
their own isolated "share servers" that export their shares on the share
network that have the ability plug into user-determined authentication
domains ("security services"). Not all Shared File System service storage
drivers support share networks. Those that do assert the capability
``driver_handles_share_servers=True``.

When creating a share type, you are *required* to set an extra-spec that
matches this capability. It is visible to end users.

Default Share Type
------------------

When you are operating a cloud where all your tenants are trusted, you may
want to create a "default" share type that applies to all of them. It
simplifies share creation for your end users since they don't need to worry
about share types.

Use of a default share type is not recommended in a multi-tenant cloud where
you may want to separate your user workloads, or offer different service
capabilities. In such instances, you must always encourage your users to
specify a share type at share creation time, and not rely on the default
share type.

.. important::

    If you do not create and configure a default share type, users *must*
    specify a valid share type during share creation, or share creation
    requests will fail.

To configure the default share type, edit the ``manila.conf`` file, and set
the configuration option [DEFAULT]/default_share_type.

You must then create a share type, using :command:`manila type-create`:

.. code-block:: console

   manila type-create [--is_public <is_public>]
                      [--description <description>]
                      [--extra-specs <other-extra-specs>]
                      <name> <spec_driver_handles_share_servers>

where:

- ``name`` is the share type name
- ``is_public`` defines the visibility for the share type (true/false)
- ``description`` is a free form text field to describe the characteristics
  of the share type for your users' benefit
- ``extra-specs`` defines a comma separated set of key=value pairs of
  optional extra specifications
- ``spec_driver_handles_share_servers`` is the mandatory extra-spec
  (true/false)

Share type operations
---------------------

To create a new share type you need to specify the name of the new share
type. You also require an extra spec ``driver_handles_share_servers``.
The new share type can be public or private.

.. code-block:: console

   $ manila manila type-create default-shares False \
     --description "Default share type for the cloud, no fancy capabilities"

   $ manila type-list
    +--------------------------------------+-----------------------------------+------------+------------+--------------------------------------+-------------------------------------------+---------------------------------------------------------+
    | ID                                   | Name                              | visibility | is_default | required_extra_specs                 | optional_extra_specs                      | Description                                             |
    +--------------------------------------+-----------------------------------+------------+------------+--------------------------------------+-------------------------------------------+---------------------------------------------------------+
    | cf1f92ec-4d0a-4b79-8f18-6bb82c22840a | default-shares                    | public     | -          | driver_handles_share_servers : False |                                           | Default share type for the cloud, no fancy capabilities |
    +--------------------------------------+-----------------------------------+------------+------------+--------------------------------------+-------------------------------------------+---------------------------------------------------------+

    $ manila type-show default-shares
    +----------------------+---------------------------------------------------------+
    | Property             | Value                                                   |
    +----------------------+---------------------------------------------------------+
    | id                   | cf1f92ec-4d0a-4b79-8f18-6bb82c22840a                    |
    | name                 | default-shares                                          |
    | visibility           | public                                                  |
    | is_default           | NO                                                      |
    | description          | Default share type for the cloud, no fancy capabilities |
    | required_extra_specs | driver_handles_share_servers : False                    |
    | optional_extra_specs |                                                         |
    +----------------------+---------------------------------------------------------+

You did not provide optional capabilities, so they are all *assumed to be off
by default*. So, Non-privileged users see some tenant-visible capabilities
explicitly.

.. code-block:: console


    $ source demorc
    $ manila type-list
    +--------------------------------------+-----------------------------------+------------+------------+--------------------------------------+--------------------------------------------+---------------------------------------------------------+
    | ID                                   | Name                              | visibility | is_default | required_extra_specs                 | optional_extra_specs                       | Description                                             |
    +--------------------------------------+-----------------------------------+------------+------------+--------------------------------------+--------------------------------------------+---------------------------------------------------------+
    | cf1f92ec-4d0a-4b79-8f18-6bb82c22840a | default-shares                    | public     | -          | driver_handles_share_servers : False | snapshot_support : False                   | Default share type for the cloud, no fancy capabilities |
    +--------------------------------------+-----------------------------------+------------+------------+--------------------------------------+--------------------------------------------+---------------------------------------------------------+

    $ manila type-show default-shares
    +----------------------+---------------------------------------------------------+
    | Property             | Value                                                   |
    +----------------------+---------------------------------------------------------+
    | id                   | cf1f92ec-4d0a-4b79-8f18-6bb82c22840a                    |
    | name                 | default-shares                                          |
    | visibility           | public                                                  |
    | is_default           | NO                                                      |
    | description          | Default share type for the cloud, no fancy capabilities |
    | required_extra_specs | driver_handles_share_servers : False                    |
    | optional_extra_specs | snapshot_support : False                                |
    |                      | create_share_from_snapshot_support : False              |
    |                      | revert_to_snapshot_support : False                      |
    |                      | mount_snapshot_support : False                          |
    +----------------------+---------------------------------------------------------+


You can set or unset extra specifications for a share type
using **manila type-key <share_type> set <key=value>** command.

.. code-block:: console

   $ manila type-key default-shares set snapshot_support=True

   $ manila type-show default-shares
    +----------------------+---------------------------------------------------------+
    | Property             | Value                                                   |
    +----------------------+---------------------------------------------------------+
    | id                   | cf1f92ec-4d0a-4b79-8f18-6bb82c22840a                    |
    | name                 | default-shares                                          |
    | visibility           | public                                                  |
    | is_default           | NO                                                      |
    | description          | Default share type for the cloud, no fancy capabilities |
    | required_extra_specs | driver_handles_share_servers : False                    |
    | optional_extra_specs | snapshot_support : True                                 |
    +----------------------+---------------------------------------------------------+

Use :command:`manila type-key <share_type> unset <key>` to unset an extra
specification.

A share type can be deleted with the :command:`manila type-delete
<share_type>` command. However, a share type can only be deleted if there
are no shares, share groups or share group types associated with the share
type.

.. _share_type_access:

Share type access control
-------------------------

You can provide access, revoke access, and retrieve list of allowed projects
for a specified private share.

Create a private type:

.. code-block:: console

   $ manila type-create my_type1 True \
            --is_public False \
            --extra-specs snapshot_support=True
   +----------------------+--------------------------------------+
   | Property             | Value                                |
   +----------------------+--------------------------------------+
   | required_extra_specs | driver_handles_share_servers : True  |
   | Name                 | my_type1                             |
   | Visibility           | private                              |
   | is_default           | -                                    |
   | ID                   | 06793be5-9a79-4516-89fe-61188cad4d6c |
   | optional_extra_specs | snapshot_support : True              |
   +----------------------+--------------------------------------+

.. note::

   If you run :command:`manila type-list` only public share types appear.
   To see private share types, run :command:`manila type-list --all``.

Grant access to created private type for a demo and alt_demo projects
by providing their IDs:

.. code-block:: console

   $ manila type-access-add my_type1 d8f9af6915404114ae4f30668a4f5ba7
   $ manila type-access-add my_type1 e4970f57f1824faab2701db61ee7efdf

To view information about access for a private share, type ``my_type1``:

.. code-block:: console

   $ manila type-access-list my_type1
   +----------------------------------+
   | Project_ID                       |
   +----------------------------------+
   | d8f9af6915404114ae4f30668a4f5ba7 |
   | e4970f57f1824faab2701db61ee7efdf |
   +----------------------------------+

After granting access to the share, the users in the allowed projects
can see the share type and use it to create shares.

To deny access for a specified project, use
:command:`manila type-access-remove <share_type> <project_id>` command.
