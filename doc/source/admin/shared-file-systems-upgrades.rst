Upgrading the Shared File System service
========================================

This document outlines steps and notes for operators for reference when
upgrading their Shared File System service (manila) from previous versions of
OpenStack. The service aims to provide a minimal downtime upgrade experience.
Since the service does not operate in the data plane, the accessibility of any
provisioned resources such as shares, share snapshots, share groups, share
replicas, share servers, security services and share networks will not be
affected during an upgrade. Clients can continue to actively use these
resources while the service control plane is being upgraded.

Plan the upgrade
----------------

It is highly recommended that you:

* update the Shared File System service to the latest code from the release
  you are currently using.
* read the `Shared File System service release notes
  <https://docs.openstack.org/releasenotes/manila/>`_ for the release that
  you intended to upgrade to. Pay special attention to the deprecations and
  upgrade notes.
* consider the impact of the service control plane upgrade to your cloud's
  users. The upgrade process interrupts provisioning of new shared
  file systems and associated resources. It also prevents management
  operations on existing shared file systems and associated resources. Data
  path access to shared file systems will remain uninterrupted.
* take a backup of the shared file system service database so you can
  rollback any failed upgrades to a previous version of the software.
  Although the ``manila-manage`` command offers a database downgrade
  command, it is not supported for production use. The only way to recover
  from a failed update is to restore the database from a backup.
* identify your Shared File System service back end storage systems/solutions
  and their drivers. Ensure that the version of each storage system is
  supported by the respective driver in the target release. If you're using
  a storage solution from a third party vendor, consult their product pages to
  determine if the solution is supported by the release of OpenStack that you
  are upgrading to. Many vendors publish a support matrix either within this
  service administration guide, or on their own websites. If you find an
  incompatibility, stop, and determine if you have to upgrade the storage
  solution first.
* develop an upgrade procedure and assess it thoroughly by using a test
  environment similar to your production environment.

Graceful service shutdown
-------------------------
Shared File System service components (scheduler, share-manager,
data-manager) are python processes listening for messages on a AMQP queue.
When the operator sends SIGTERM signal to the process, they stop getting new
work from the queue, complete any outstanding work and then terminate.

Database Migration
------------------
The Shared File System service only supports cold upgrades, meaning that the
service plane is expected to be down during the database upgrade. Database
upgrades include schema changes as well as data migrations to accommodate
newer versions of the schema. Once upgraded, downgrading the database is not
supported. When the database has been upgraded, older services may misbehave
when accessing database objects, so ensure all ``manila-*`` services are down
before you upgrade the database.

Prune deleted database rows
---------------------------
Shared File System service resources are soft deleted in the database, so
users are able to track instances in the DB that are created and destroyed
in production. Soft-deletion also helps cloud operators adhere to data
retention policies. Not purging soft-deleted entries affects DB performance as
indices grow very large and data migrations take longer as there is more
data to migrate. It is recommended that you prune the service database before
upgrading to prevent unnecessary data migrations. Pruning permanently
deletes soft deleted database records.

.. code::

 manila-manage db purge <age_in_days>

Upgrade procedure
-----------------

#. Ensure you're running the latest Shared File System service packages for
   the OpenStack release that you currently use.
#. Run the ``manila-status upgrade check`` command to validate that the service
   is ready for upgrade.
#. Backup the manila database
#. Gracefully stop all Shared File System service processes. We recommend in
   this order: manila-api, manila-scheduler, manila-share and manila-data.

.. note::

  The manila-data service may be processing time consuming data migrations.
  Shutting it down will interrupt any ongoing migrations, and these will not
  be automatically started when the service comes back up. You can check
  the status on ongoing migrations with ``manila migration-get-progress``
  command; issue ``manila migration-complete`` for any ongoing migrations
  that have completed their data copy phase.

#. Upgrade all the service packages. If upgrading from distribution packages,
   your system package manager is expected to handle this automatically.
#. Fix any deprecated configuration options used.
#. Fix any deprecated api policies used.
#. Run ``manila-manage db sync`` from any node with the latest manila
   packages.
#. Start all the Shared File System service processes.
#. Inspect the ``services`` by running ``manila service-list``. If there are
   any orphaned records, run ``manila-manage service cleanup`` to delete them.

Upgrade testing
---------------

The Shared File System service code is continually tested for upgrade from
a previous release to the current release using `Grenade <https://docs
.openstack.org/grenade/latest/>`_. Grenade is an OpenStack test harness project
that validates upgrade scenarios between releases. It uses DevStack to
initially perform a base OpenStack install and then upgrade to a target
version. Tests include the creation of a variety of Shared File System
service resources on the prior release, and verification for their existence
and functionality after the upgrade.
