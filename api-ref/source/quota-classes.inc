.. -*- rst -*-

Quota class set
===============

Quota classes can be shown and updated for a project.

.. important::
    Share replicas and replica gigabytes were added to quota management
    APIs in API version 2.53.
    Per share gigabytes was added to quota management APIs in API
    version 2.62.
    Share backups and backup gigabytes were added to quota management
    APIs in API version 2.80.


Show quota classes for a project
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/quota-class-sets/{quota_class_name}

Shows quota class set for a project. If no specific value for the quota class
resource exists, then the default value will be reported.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 403
   - 404

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - quota_class_name: quota_class_name


Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - quota_class_set: quota_class_set
   - share_groups: maxTotalShareGroups
   - gigabytes: maxTotalShareGigabytes
   - share_group_snapshots: maxTotalShareGroupSnapshots
   - snapshots: maxTotalShareSnapshots
   - snapshot_gigabytes: maxTotalSnapshotGigabytes
   - shares: maxTotalShares
   - id: quota_class_id
   - share_networks: maxTotalShareNetworks
   - share_replicas: maxTotalShareReplicas
   - replica_gigabytes: maxTotalReplicaGigabytes
   - per_share_gigabytes: perShareGigabytes
   - backups: maxTotalShareBackups
   - backup_gigabytes: maxTotalBackupGigabytes

Response Example
----------------

.. literalinclude:: ./samples/quota-classes-show-response.json
   :language: javascript


Update quota classes for a project
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  PUT /v2/quota-class-sets/{quota_class_name}

Updates quota class set for a project. If the ``quota_class_name`` key does not
exist, then the API will create one.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 403
   - 404

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - quota_class_name: quota_class_name
   - shares: maxTotalSharesOptional
   - snapshots: maxTotalShareSnapshotsOptional
   - gigabytes: maxTotalShareGigabytesOptional
   - snapshot-gigabytes: maxTotalSnapshotGigabytesOptional
   - share-networks: maxTotalShareNetworksOptional
   - share-replicas: maxTotalShareReplicasOptional
   - replica-gigabytes: maxTotalReplicaGigabytesOptional
   - per-share-gigabytes: perShareGigabytesOptional
   - backups: maxTotalShareBackupsOptional
   - backup-gigabytes: maxTotalBackupGigabytesOptional

Request Example
---------------

.. literalinclude:: ./samples/quota-classes-update-request.json
   :language: javascript


Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - quota_class_set: quota_class_set
   - share_groups: maxTotalShareGroups
   - gigabytes: maxTotalShareGigabytes
   - share_group_snapshots: maxTotalShareGroupSnapshots
   - snapshots: maxTotalShareSnapshots
   - snapshot_gigabytes: maxTotalSnapshotGigabytes
   - shares: maxTotalShares
   - share_networks: maxTotalShareNetworks
   - share_replicas: maxTotalShareReplicas
   - replica_gigabytes: maxTotalReplicaGigabytes
   - per_share_gigabytes: perShareGigabytes
   - backups: maxTotalShareBackups
   - backup_gigabytes: maxTotalBackupGigabytes

Response Example
----------------

.. literalinclude:: ./samples/quota-classes-update-response.json
   :language: javascript
