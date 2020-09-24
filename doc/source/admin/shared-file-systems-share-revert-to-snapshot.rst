.. _shared_file_systems_share_revert_to_snapshot:

========================
Share revert to snapshot
========================

To revert a share to the latest available snapshot, use the
:command:`manila revert-to-snapshot`.

.. note::
    - In order to use this feature, the available backend in your deployment
      must have support for it. The list of backends that support this feature
      in the manila can be found in the :doc:`share_back_ends_feature_support_mapping`.
    - This feature is only available in API version 2.27 and beyond. To create
      shares that are revertible, the share type used must contain the extra-spec
      ``revert_to_snapshot_support`` set to ``True``. The default value for
      this is ``False``.
    - The revert operation can only be performed to the most recent available
      snapshot of the share known to manila. If revert to an earlier snapshot
      is desired, later snapshots must explicitly be deleted. In order to
      determine the most recent snapshot, the ``created_at`` field on the
      snapshot object is used.

While reverting, the share is in ``reverting`` status and the snapshot is in
``restoring`` status. After a successful restoration, the share and snapshot
states will again be set to ``available``. If the restoration fails
the share will be set to ``reverting_error`` state and the snapshot will be
set to ``available``.

When a replicated share is reverted, the share becomes ready to be used only
when all ``active`` replicas have been reverted. All secondary replicas will
remain in ``out-of-sync`` state until they are consistent with the ``active``
replicas.

To revert a share to a snapshot, run:

.. code-block:: console

   $ manila revert-to-snapshot 14ee8575-aac2-44af-8392-d9c9d344f392
