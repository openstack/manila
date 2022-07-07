.. _shared_file_systems_share_group_types:

=================
Share group types
=================

Share group types are types for share groups just like :ref:`share types for
shares<shared_file_systems_share_types>`.
A group type is associated with group specs similar to the way extra specs are
associated with a share type.

A share group type aids the scheduler to filter or choose back ends when you
create a share group and to set any backend specific parameters on the share
group. Any driver that can perform a group operation in an advantaged way may
report that as a group capability, such as:

* Ordered writes
* Consistent snapshots
* Group replication
* Group backup

Share group types may contain group specs corresponding to the group
capabilities reported by the backends. A group capability applies across all
the shares inside the share group, for example, a backend may support
`consistent_snapshot_support`, and using this group type extra spec in the
group type will allow scheduling share groups onto that backend. Any time a
snapshot of the group is initiated, a crash consistent simultaneous snapshot
of all the constituent shares is taken.
Shares in a share group may each have different share types because they can
each be on separate pools, have different capabilities and perhaps end users
can even be billed differently for using each of them. To allow for this
possibility, one or more share types can be associated with a group type. The
admin also specifies which share type(s) a given group type may contain.
At least one share type must be provided to create a share group type.
When an user creates a share group, the scheduler creates the group on one of
the backends that match the specified share type(s) and share group type.

In the Shared File Systems configuration file ``manila.conf``, the
administrator can set the share group type used by default for the share group
creation.

To create a share group type, use :command:`manila share-group-type-create` command as:

.. code-block:: console

   manila share-group-type-create [--is_public <is_public>]
                                  [--group-specs [<key=value> [<key=value> ...]]]
                                  <name> <share_types>


Where the ``name`` is the share group type name and ``--is_public`` defines
the level of the visibility for the share group type. One share group can
include multiple ``share_types``. ``--group-specs`` are the extra
specifications used to filter back ends.

.. note::

   The extra specifications set in the share group types are explained further
   in :ref:`shared_file_systems_scheduling`.

Administrators can create share group types with these extra specifications for
the back ends filtering.
An administrator can use the ``policy.yaml`` file to grant permissions for
share group type creation with extra specifications to other roles.

You set a share group type to private or public and
:ref:`manage the access<share_group_type_access>` to the private share group types. By
default a share group type is created as publicly accessible. Set
``--is_public`` to ``False`` to make the share group type private.

Share group type operations
---------------------------

To create a new share group type you need to specify the name of the new share
group type and existing share types. The new share group type can also be public.
One share group can include multiple share types.

.. code-block:: console

   $ manila share-group-type-create group_type_for_cg default_share_type --is_public True
   +------------+--------------------------------------+
   | Property   | Value                                |
   +------------+--------------------------------------+
   | is_default | -                                    |
   | ID         | cfe42f20-d13e-4348-9370-f0763e426db3 |
   | Visibility | public                               |
   | Name       | group_type_for_cg                    |
   +------------+--------------------------------------+

   $ manila share-group-type-list
   +--------------------------------------+-------------------+------------+------------+
   | ID                                   | Name              | visibility | is_default |
   +--------------------------------------+-------------------+------------+------------+
   | cfe42f20-d13e-4348-9370-f0763e426db3 | group_type_for_cg | public     | -          |
   +--------------------------------------+-------------------+------------+------------+

You can set or unset extra specifications for a share group type
using **manila share-group-type-key <share_group_type> set <key=value>** command.

.. code-block:: console

   $ manila share-group-type-key group_type_for_cg set consistent_snapshot_support=host

It is also possible to view a list of current share group types and extra
specifications:

.. code-block:: console

   $ manila share-group-type-specs-list
   +--------------------------------------+-------------------+------------------------------------+
   | ID                                   | Name              | all_extra_specs                    |
   +--------------------------------------+-------------------+------------------------------------+
   | cfe42f20-d13e-4348-9370-f0763e426db3 | group_type_for_cg | consistent_snapshot_support : host |
   +--------------------------------------+-------------------+------------------------------------+


Use :command:`manila share-group-type-key <share_group_type> unset <key>` to
unset an extra specification.

A public or private share group type can be deleted with the
:command:`manila share-group-type-delete <share_group_type>` command.

.. _share_group_type_access:

Share group type access
-----------------------

You can manage access to a private share group type for different projects.
Administrators can provide access, revoke access, and retrieve
information about access for a specified private share group.

Create a private group type:

.. code-block:: console

   $ manila share-group-type-create my_type1 default_share_type --is_public False
   +------------+--------------------------------------+
   | Property   | Value                                |
   +------------+--------------------------------------+
   | is_default | -                                    |
   | ID         | f57cf3db-2503-4c0f-915c-4f1335d95465 |
   | Visibility | private                              |
   | Name       | my_type1                             |
   +------------+--------------------------------------+

.. note::

   If you run :command:`manila share-group-type-list` only public share group
   types appear. To see private share group types, run :command:`manila
   share-group-type-list` with ``--all`` optional argument.

Grant access to created private type for a demo and alt_demo projects
by providing their IDs:

.. code-block:: console

   $ manila share-group-type-access-add my_type1 d8f9af6915404114ae4f30668a4f5ba7
   $ manila share-group-type-access-add my_type1 e4970f57f1824faab2701db61ee7efdf

To view information about access for a private share, :command:`manila type-access-list my_type1`:

.. code-block:: console

   $ manila type-access-list my_type1
   +----------------------------------+
   | Project_ID                       |
   +----------------------------------+
   | d8f9af6915404114ae4f30668a4f5ba7 |
   | e4970f57f1824faab2701db61ee7efdf |
   +----------------------------------+

After granting access to the share group type, the target project
can see the share group type in the list, and create private
share groups.

To deny access for a specified project, use
:command:`manila share-group-type-access-remove <share_group_type> <project_id>` command.

.. code-block:: console

   $ manila share-group-type-access-remove my_type1 e4970f57f1824faab2701db61ee7efdf
