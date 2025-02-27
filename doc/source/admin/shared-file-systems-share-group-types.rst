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

To create a share group type, use :command:`openstack share group type create` command as:

.. code-block:: console

   openstack share group type create [-h]
                                         [-f {json,shell,table,value,yaml}]
                                         [-c COLUMN] [--noindent]
                                         [--prefix PREFIX]
                                         [--max-width <integer>]
                                         [--fit-width] [--print-empty]
                                         [--group-specs [<key=value> ...]]
                                         [--public <public>]
                                         <name> <share-types>
                                         [<share-types> ...]


Where the ``name`` is the share group type name and ``--public`` defines
the level of the visibility for the share group type. One share group can
include multiple ``share-types``. ``--group-specs`` are the extra
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
``--public`` to ``False`` to make the share group type private.

Share group type operations
---------------------------

To create a new share group type you need to specify the name of the new share
group type and existing share types. The new share group type can also be public.
One share group can include multiple share types.

.. code-block:: console

   $ openstack share group type create group_type_for_cg default --public True
   +-------------+--------------------------------------+
   | Field       | Value                                |
   +-------------+--------------------------------------+
   | id          | cd7173f2-93f9-4977-aa55-eb8884333a07 |
   | name        | group_type_for_cg                    |
   | share_types | c069126a-2d87-4bbb-a395-1dc5a5ac5d96 |
   | visibility  | public                               |
   | is_default  | False                                |
   | group_specs |                                      |
   +-------------+--------------------------------------+

   $ openstack share group type list
   +--------------------------------------+-------------------+--------------------------------------+------------+------------+-------------+
   | ID                                   | Name              | Share Types                          | Visibility | Is Default | Group Specs |
   +--------------------------------------+-------------------+--------------------------------------+------------+------------+-------------+
   | cd7173f2-93f9-4977-aa55-eb8884333a07 | group_type_for_cg | c069126a-2d87-4bbb-a395-1dc5a5ac5d96 | public     | False      |             |
   +--------------------------------------+-------------------+--------------------------------------+------------+------------+-------------+

You can set extra specifications for a share group type
using **openstack share group type set <share_group_type> --group-specs <key=value>** command.

.. code-block:: console

   $ openstack share group type set group_type_for_cg --group-specs consistent_snapshot_support=host

It is also possible to view a list of current share group types and extra
specifications:

.. code-block:: console

   $ openstack share group type list
   +--------------------------------------+-------------------+--------------------------------------+------------+------------+------------------------------------+
   | ID                                   | Name              | Share Types                          | Visibility | Is Default | Group Specs                        |
   +--------------------------------------+-------------------+--------------------------------------+------------+------------+------------------------------------+
   | cd7173f2-93f9-4977-aa55-eb8884333a07 | group_type_for_cg | c069126a-2d87-4bbb-a395-1dc5a5ac5d96 | public     | False      | consistent_snapshot_support : host |
   +--------------------------------------+-------------------+--------------------------------------+------------+------------+------------------------------------+


Use :command:`openstack share group type unset <share_group_type> <key>` to
unset one or more extra specifications.

.. code-block:: console

   $ openstack share group type unset test_group_type mount_snapshot_support

A public or private share group type can be deleted with the
:command:`openstack share group type delete <share_group_type>` command.

.. _share_group_type_access:

Share group type access
-----------------------

You can manage access to a private share group type for different projects.
Administrators can provide access, revoke access, and retrieve
information about access for a specified private share group type.

Create a private group type:

.. code-block:: console

   $ openstack share group type create my_type1 default --public False
   +-------------+--------------------------------------+
   | Field       | Value                                |
   +-------------+--------------------------------------+
   | id          | 0c488ca6-8843-4313-ba2b-cc33acb2af73 |
   | name        | my_type1                             |
   | share_types | c069126a-2d87-4bbb-a395-1dc5a5ac5d96 |
   | visibility  | private                              |
   | is_default  | False                                |
   | group_specs |                                      |
   +-------------+--------------------------------------+

.. note::

   If you run :command:`openstack share group type list` both public and private share group
   types appear.

Grant access to created private type for a demo and alt_demo projects
by providing their IDs:

.. code-block:: console

   $ openstack share group type access create my_type1 63ce0a1452384fce9edb0189425ea0e2
   $ openstack share group type access create my_type1 d274cfc59e2543d38aa223af4f5eb327

To view information about access for a private share group type, use the command  :command:`openstack share group type access list my_type1`:

.. code-block:: console

   $ openstack share group type access list my_type1
   +----------------------------------+
   | Project ID                       |
   +----------------------------------+
   | 63ce0a1452384fce9edb0189425ea0e2 |
   | d274cfc59e2543d38aa223af4f5eb327 |
   +----------------------------------+

After granting access to the share group type, the target project
can see the share group type in the list, and create private
share groups.

To deny access for a specified project, use
:command:`openstack share group type access delete <share_group_type> <project_id>` command.

.. code-block:: console

   $ openstack share group type access delete my_type1 b0fa13353e594d6f809dfa405fedc46a
