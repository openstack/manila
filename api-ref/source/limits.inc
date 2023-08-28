.. -*- rst -*-

Limits
======

Limits are the resource limitations that are allowed for each
tenant (project). An administrator can configure limits in the
``manila.conf`` file.

Users can query their rate and absolute limits. The absolute limits
contain information about:

- Total maximum share memory, in GiBs.

- Number of share-networks.

- Number of share-snapshots.

- Number of shares.

- Shares and total used memory, in GiBs.

- Snapshots and total used memory, in GiBs.

- Number of share replicas (since API version 2.53).

- Share replicas and total used memory, in GiBs (since API version 2.53).

Rate limits control the frequency at which users can issue specific
API requests. Administrators use rate limiting to configure limits
on the type and number of API calls that can be made in a specific
time interval. For example, a rate limit can control the number of
GET requests that can be processed during a one-minute period.


List share limits
~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/limits

Lists share limits.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - maxTotalShareGigabytes: maxTotalShareGigabytes
   - maxTotalSnapshotGigabytes: maxTotalSnapshotGigabytes
   - maxTotalShares: maxTotalShares
   - maxTotalShareSnapshots: maxTotalShareSnapshots
   - maxTotalShareNetworks: maxTotalShareNetworks
   - maxTotalShareReplicas: maxTotalShareReplicas
   - maxTotalReplicaGigabytes: maxTotalReplicaGigabytes
   - maxTotalShareBackups: maxTotalShareBackups
   - maxTotalBackupGigabytes: maxTotalBackupGigabytes
   - totalSharesUsed: totalSharesUsed
   - totalShareSnapshotsUsed: totalShareSnapshotsUsed
   - totalShareNetworksUsed: totalShareNetworksUsed
   - totalShareGigabytesUsed: totalShareGigabytesUsed
   - totalSnapshotGigabytesUsed: totalSnapshotGigabytesUsed
   - totalShareReplicasUsed: totalShareReplicasUsed
   - totalReplicaGigabytesUsed: totalReplicaGigabytesUsed
   - totalShareBackupsUsed: totalShareBackupsUsed
   - totalBackupGigabytesUsed: totalBackupGigabytesUsed
   - uri: uri
   - regex: regex
   - value: value
   - verb: verb
   - remaining: remaining
   - unit: unit
   - next-available: next-available

Response example
----------------

.. literalinclude:: samples/limits-response.json
   :language: javascript
