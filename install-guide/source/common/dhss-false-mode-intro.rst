Shared File Systems Option 1: No driver support for share servers management
----------------------------------------------------------------------------

For simplicity, this configuration references the same storage node
configuration for the Block Storage service. However, the LVM driver
requires a separate empty local block storage device to avoid conflict
with the Block Storage service. The instructions use ``/dev/sdc``, but
you can substitute a different value for your particular node.
