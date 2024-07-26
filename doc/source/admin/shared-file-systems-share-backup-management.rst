.. _shared-file-systems-share-backup-management:

=======================
Share backup management
=======================

Share backup management is the feature that provides the capability to create
a backup for the given share, restore a backup, and delete a backup. It is a
valuable feature for most shared file system users, especially for NAS users.

Use cases
~~~~~~~~~

As an administrator, you may want to backup and restore your share so that
archival can be made simpler and you can bring back the old data
whenever required. It includes:

* Create a backup
* Delete a backup
* Restore a backup in specified share


Backup/Restore workflows
~~~~~~~~~~~~~~~~~~~~~~~~

Starting from 2023.2, a generic approach for backing up shares through the
manila data service has been implemented where the backup of the shares can be
stored on a NFS path which are mounted on control nodes. This driver matches
the workflows of cinder NFSBackupDriver and thus it helps users with
less learning time, and provides the basic backup ability. The vendor
that supports NFS, must provide space for NFS to interconnect with NFS backup
drivers. The implementation of NFS backup driver will be generic though. The
backup process for this driver consists of:

* Make sure share is in available state and not busy.
* Allow read access to share and write access to backup share.
* Mount the share and backend driver's share(i.e. backup share) to the
  data service node.
* Copy data from share to backup share.
* Unmount the share and backup share.
* Deny access to share and backup share.

For the generic NFS backup approach, only one backup backend is allowed for
simplicity, at the moment. By default no backup driver will be enabled. To
enable the backup driver, use the below configurations in manila.conf

.. code-block:: console

   backup_driver = manila.data.drivers.nfs.NFSBackupDriver
   backup_mount_export = <NFS_Server>:/<NFS_Data_Path>
   backup_mount_options = '-o vers=<version>',minorversion=1

New status for backup and share:

* backup

  * creating
  * available
  * deleting
  * deleted
  * error_deleting
  * backup_restoring
  * error

* share

  * backing_creating
  * backup_restoring
  * backup_restoring_error

During backup, share will be marked as busy and other operations on share
such as delete, soft_delete, migration, extend, shrink, ummanage,
revert_to_snapshot, crate_snapshot, create_replica etc can not be performed
unless share becomes available. Finally, whether or not the share is
successfully backed up, the state of the share is rolled back to the
available state. In case the backup fails, share task_state will contain the
failure information. Also, failure message will be recorded.

New clean up actions:
The backup and restore actions could break when service is down, so new
clean up action will be added to reset the status and clean temporary
files (if involved).

New quotas for backup :

* ``quota_backups``: indicate the share backups allowed per project.

* ``quota_backup_gigabytes``: indicate the total amount of storage, in
  gigabytes, allowed for backups per project.

Using the backup APIs (CLI):
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The commands to interact with the share backup API are:

* ``openstack share backup create``: It creates a backup for the share on the
  NFS path. The backup becomes creating and it becomes availabe when the backup
  is completed.

  .. code-block:: console

     $ openstack share backup create --help # to see the help of all the
     available options

     $ openstack share backup create --name manila_backup1 25a6f80e-306e-4bb8-ad27-cf6800955228
     +-------------------+--------------------------------------+
     | Field             | Value                                |
     +-------------------+--------------------------------------+
     | availability_zone | manila-zone-0                        |
     | created_at        | 2024-03-21T12:49:35.719214           |
     | description       | None                                 |
     | host              | None                                 |
     | id                | c2022366-0701-44d2-b48b-aa95a666efa5 |
     | name              | manila_backup1                       |
     | progress          | 0                                    |
     | restore_progress  | 0                                    |
     | share_id          | 25a6f80e-306e-4bb8-ad27-cf6800955228 |
     | size              | 1                                    |
     | status            | creating                             |
     | topic             | None                                 |
     | updated_at        | None                                 |
     +-------------------+--------------------------------------+

* ``openstack share backup list``: It prints the current status of the backup.
  It is set to ``available`` if all operations succeeded.

  .. code-block:: console

     $ openstack share backup list
     +--------------------------------------+----------------+--------------------------------------+-----------+
     | ID                                   | Name           | Share ID                             | Status    |
     +--------------------------------------+----------------+--------------------------------------+-----------+
     | c2022366-0701-44d2-b48b-aa95a666efa5 | manila_backup1 | 25a6f80e-306e-4bb8-ad27-cf6800955228 | available |
     +--------------------------------------+----------------+--------------------------------------+-----------+
     $


* ``openstack share backup show``: It obtains the latest information of the
  backup.

  .. code-block:: console

     $ openstack share backup show c2022366-0701-44d2-b48b-aa95a666efa5
     +-------------------+--------------------------------------+
     | Field             | Value                                |
     +-------------------+--------------------------------------+
     | availability_zone | manila-zone-0                        |
     | created_at        | 2024-03-21T12:49:36.000000           |
     | description       | None                                 |
     | host              | vm.openstack.opendev.com             |
     | id                | c2022366-0701-44d2-b48b-aa95a666efa5 |
     | name              | manila_backup1                       |
     | progress          | 100                                  |
     | restore_progress  | 0                                    |
     | share_id          | 25a6f80e-306e-4bb8-ad27-cf6800955228 |
     | size              | 1                                    |
     | status            | available                            |
     | topic             | manila-data                          |
     | updated_at        | 2024-03-21T12:50:07.000000           |
    +-------------------+--------------------------------------+
     $

* ``openstack share backup set``: It sets the name and description for the
  backup.

  .. code-block:: console

     $ openstack share backup set c2022366-0701-44d2-b48b-aa95a666efa5 --name "new_name" --description "backup_taken_on_march_21"

  .. note::
     This command has no output.

  .. code-block:: console

     $ openstack share backup show c2022366-0701-44d2-b48b-aa95a666efa5
     +-------------------+--------------------------------------+
     | Field             | Value                                |
     +-------------------+--------------------------------------+
     | availability_zone | manila-zone-0                        |
     | created_at        | 2024-03-21T12:49:36.000000           |
     | description       | backup_taken_on_march_21             |
     | host              | vm.openstack.opendev.com             |
     | id                | c2022366-0701-44d2-b48b-aa95a666efa5 |
     | name              | new_name                             |
     | progress          | 100                                  |
     | restore_progress  | 0                                    |
     | share_id          | 25a6f80e-306e-4bb8-ad27-cf6800955228 |
     | size              | 1                                    |
     | status            | available                            |
     | topic             | manila-data                          |
     | updated_at        | 2024-03-21T12:57:09.000000           |
     +-------------------+--------------------------------------+


Using the backup APIs (REST):
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

APIs will be experimental, until some cycles of testing, and the eventual
graduation of them. You can refer to this link for more information
`REST API Support <https://docs.openstack.org/api-ref/shared-file-system/
index.html#share-backups-since-api-v2-80>`_

Backup/Restore via backup types (Vendor specific)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There are use cases such that, the individual storage vendors/drivers might
have robust solution in their own storage to backup the data. When such
features are available in the storage, the individual drivers can be enhanced
to build their own backup solutions by extending the existing manila backup
drivers with the use of backup types. Thus shares created in Manila on such
storage, can be easily backed up via vendor specific solutions.

.. note::
   `backup_type` was added to backup API responses in version 2.85.

Starting from 2024.1, a concept named ``backup_type`` has been introduced.
This is needed for creating backups with third party drivers, in case an
implementation is available. The ``backup_type`` is a construct which should
have backup specific parameters such as ``backup_type_name``


.. note::
   The sample config will look like this:
   ``eng_data_backup`` is the backup_type here.::

       [eng_data_backup]
       backup_type_name=my_backup

       [nas_storage]
       enabled_backup_types = eng_data_backup

Backup/Restore workflows via backup type:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Users can create, delete and restore backups on vendor specific storage using
backup_type.

.. note::
   Before using this feature, you need to check with your storage partner for
   the availability of this feature in Manila drivers.

The workflow of creating, viewing, restoring and deleting backups captured
below for user reference.

  .. code-block:: console

     $ openstack share backup list
     +--------------------------------------+-------+--------------------------------------+-----------+
     | ID                                   | Name  | Share ID                             | Status    |
     +--------------------------------------+-------+--------------------------------------+-----------+
     | 8a9b3ce0-23bb-4923-b8ce-d0dd1f56b2b8 | test4 | 983c6dd5-ef93-4c73-9359-ef02fe3bbce7 | available |
     +--------------------------------------+-------+--------------------------------------+-----------+

     $ openstack share backup create --name test5 --backup-options backup_type=eng_data_backup source_share
     +-------------------+--------------------------------------+
     | Field             | Value                                |
     +-------------------+--------------------------------------+
     | availability_zone | manila-zone-0                        |
     | backup_type       | backup_type1                         |
     | created_at        | 2024-03-11T18:15:32.183982           |
     | description       | None                                 |
     | host              | vm.openstack.opendev.com@nas_storage |
     | id                | 4b468327-d03f-4df7-97ef-c5230b5beafc |
     | name              | test5                                |
     | progress          | 0                                    |
     | restore_progress  | 0                                    |
     | share_id          | 983c6dd5-ef93-4c73-9359-ef02fe3bbce7 |
     | size              | 1                                    |
     | status            | creating                             |
     | topic             | None                                 |
     | updated_at        | None                                 |
     +-------------------+--------------------------------------+

     $ openstack share backup list
     +--------------------------------------+-------+--------------------------------------+-----------+
     | ID                                   | Name  | Share ID                             | Status    |
     +--------------------------------------+-------+--------------------------------------+-----------+
     | 4b468327-d03f-4df7-97ef-c5230b5beafc | test5 | 983c6dd5-ef93-4c73-9359-ef02fe3bbce7 | creating  |
     | 8a9b3ce0-23bb-4923-b8ce-d0dd1f56b2b8 | test4 | 983c6dd5-ef93-4c73-9359-ef02fe3bbce7 | available |
     +--------------------------------------+-------+--------------------------------------+-----------+

     $ openstack share backup show test5
     +-------------------+------------------------------------------------+
     | Field             | Value                                          |
     +-------------------+------------------------------------------------+
     | availability_zone | manila-zone-0                                  |
     | backup_type       | backup_type1                                   |
     | created_at        | 2024-03-11T18:15:32.000000                     |
     | description       | None                                           |
     | host              | scs000215254-1.nb.openenglab.netapp.com@ontap1 |
     | id                | 4b468327-d03f-4df7-97ef-c5230b5beafc           |
     | name              | test5                                          |
     | progress          | 0                                              |
     | restore_progress  | 0                                              |
     | share_id          | 983c6dd5-ef93-4c73-9359-ef02fe3bbce7           |
     | size              | 1                                              |
     | status            | creating                                       |
     | topic             | manila-share                                   |
     | updated_at        | 2024-03-11T18:15:32.000000                     |
     +-------------------+------------------------------------------------+

     $ openstack share backup list
     +--------------------------------------+-------+--------------------------------------+-----------+
     | ID                                   | Name  | Share ID                             | Status    |
     +--------------------------------------+-------+--------------------------------------+-----------+
     | 4b468327-d03f-4df7-97ef-c5230b5beafc | test5 | 983c6dd5-ef93-4c73-9359-ef02fe3bbce7 | available |
     | 8a9b3ce0-23bb-4923-b8ce-d0dd1f56b2b8 | test4 | 983c6dd5-ef93-4c73-9359-ef02fe3bbce7 | available |
     +--------------------------------------+-------+--------------------------------------+-----------+

     $ openstack share backup restore test4

     $ openstack share backup list
     +--------------------------------------+-------+--------------------------------------+-----------+
     | ID                                   | Name  | Share ID                             | Status    |
     +--------------------------------------+-------+--------------------------------------+-----------+
     | 4b468327-d03f-4df7-97ef-c5230b5beafc | test5 | 983c6dd5-ef93-4c73-9359-ef02fe3bbce7 | available |
     | 8a9b3ce0-23bb-4923-b8ce-d0dd1f56b2b8 | test4 | 983c6dd5-ef93-4c73-9359-ef02fe3bbce7 | restoring |
     +--------------------------------------+-------+--------------------------------------+-----------+

     $ openstack share backup delete test5


