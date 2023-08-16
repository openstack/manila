:tocdepth: 3

=======================
Shared File Systems API
=======================

This is a reference for version 2 of the OpenStack Shared File Systems API
which is provided by the Manila project. Manila provides a RESTful HTTP service
through which it offers on-demand, scalable, self-service access to
shared file system storage resources.

.. important::

   Prior to the Wallaby release, Shared File System service required the
   caller to specify their "project_id" in the API URLs. This requirement has
   been dropped. The API service now behaves the same way whether or not
   "project_id" is included in the URLs. If your cloud does not yet support
   version 2.60, all the resource URLs below will require a project ID. For
   example:

   GET /v2/{project_id}/shares

.. rest_expand_all::

.. include:: versions.inc
.. include:: extensions.inc
.. include:: limits.inc
.. include:: shares.inc
.. include:: share-export-locations.inc
.. include:: share-metadata.inc
.. include:: share-actions.inc
.. include:: snapshots.inc
.. include:: snapshot-metadata.inc
.. include:: snapshot-instances.inc
.. include:: share-replicas.inc
.. include:: share-replica-export-locations.inc
.. include:: share-networks.inc
.. include:: share-network-subnets.inc
.. include:: share-network-subnets-metadata.inc
.. include:: security-services.inc
.. include:: share-servers.inc
.. include:: share-instances.inc
.. include:: share-instance-export-locations.inc
.. include:: share-types.inc
.. include:: scheduler-stats.inc
.. include:: services.inc
.. include:: availability-zones.inc
.. include:: os-share-manage.inc
.. include:: quota-sets.inc
.. include:: quota-classes.inc
.. include:: user-messages.inc
.. include:: share-access-rules.inc
.. include:: share-access-rule-metadata.inc
.. include:: share-groups.inc
.. include:: share-group-types.inc
.. include:: share-group-snapshots.inc
.. include:: share-transfers.inc
.. include:: resource-locks.inc

======================================
Shared File Systems API (EXPERIMENTAL)
======================================

.. rest_expand_all::

.. include:: experimental.inc
.. include:: share-migration.inc
.. include:: share-server-migration.inc
.. include:: share-backups.inc
