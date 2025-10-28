.. _deferred_deletion:

Deferred Share / Snapshot Deletion
==================================

Overview
--------

Manila supports deferred deletion for shares and snapshots, a feature
introduced in Manila during the 2024.1 (Caracal) release cycle.
When this feature is enabled, deletion requests release quotas
immediately, but the actual deletion in the backend driver happens
asynchronously.

Resources that encounter deletion errors are retried periodically.


Configuration Options
---------------------

To enable or disable deferred deletion, edit your ``manila.conf`` file:

.. code-block:: ini

    [DEFAULT]
    is_deferred_deletion_enabled = false

    # Whether to delete shares and share snapshots in a deferred manner.
    # When set to True, quotas are released immediately when a deletion
    # request is accepted.
    # Even with deferred deletion enabled, deletions may eventually fail,
    # and rectifying them will require manual intervention. (boolean value)

    [DEFAULT]
    periodic_deferred_delete_interval = 300

    # Interval, in seconds, at which the share manager will attempt to delete
    # shares and snapshots in the backend driver. (integer value)

Deletion Workflow
-----------------

1. A user requests deletion of a share or snapshot.
2. If deferred deletion is enabled, Manila:

   - Releases quotas immediately.
   - Marks the resource for deferred deletion.
   - Hides the resource from non-admin users in list/show API calls.

3. Periodic tasks in the share manager attempt deletion in the backend
   driver based on the interval defined in
   ``periodic_deferred_delete_interval``.
4. If deletion fails, the resource is put in the
   ``error_deferred_deleting`` state and retried in subsequent periodic
   tasks.

Error Handling
--------------

Deferred deletion can fail due to various reasons, such as driver errors,
network failures, or backend misconfiguration. Try to correct any issues
preventing deletion.

1. **Check Resource State:** Use the `openstack share list` command with admin
   credentials to identify resources in the `error_deferred_deleting` state.

2. **Retry Periodic Task:** After correcting any driver or network issues, the
   periodic task will retry deletion automatically during the next run cycle.
