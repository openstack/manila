.. _shared_mount_point_name:

Mount Point Name Support
========================

The Shared File Systems service supports user defined mount point names.
This feature allows users to specify a custom `mount_point_name` during
share creation, which will be reflected in the share's export location.
However, for this feature to be available to users, administrators must
enable an extra-spec in the share type, `mount_point_name_support`, and
set an extra-spec named `provisioning:mount_point_prefix`.

If the `provisioning:mount_point_prefix` extra-spec is not set, the
`project_id` from the `RequestContext` is used as a fallback. However,
using the `project_id` as a prefix can restrict the transfer of share
ownership, and manual action required to facilitate the transfer.

.. note::

   - In order to use this feature, the available backend in your deployment
     must have support for it. The list of backends that support this feature
     in the manila can be found in the
     :doc:`share_back_ends_feature_support_mapping`.
   - This feature is only available in API version 2.84 and beyond.
   - The extra-spec type `mount_point_name_support` required for
     this feature to work.
   - When the `project_id` is used as a prefix due to the absence of the
     `provisioning:mount_point_prefix` extra-spec, the transfer of share
     ownership may be restricted, and manual action may be required.

Administrator Guide
===================

1. **Configuring `mount_point_name_support` and
   `provisioning:mount_point_prefix`**

   .. code-block:: bash

      openstack share type set <share_type> --extra-spec \
      mount_point_name_support="<is> True"
      provisioning:mount_point_prefix=<prefix>


   Replace `<share_type>` with the name of the share type you are configuring,
   and `<prefix>` with the desired prefix. The `<prefix>` should be a string
   containing ASCII alphabets and optionally, the underscore character.

2. **Default Behavior and Security Considerations**

   If `provisioning:mount_point_prefix` is not set, the system will use the
   `project_id` as the default prefix for the `mount_point_name`. However, be
   aware that setting `provisioning:mount_point_prefix` to a constant string
   and sharing the share type with multiple projects could potentially leak
   information about the existence of other shares. This could be considered a
   security hole and should be avoided.

3. **Share Transfer**

   During a share transfer, if `provisioning:mount_point_prefix` contains a
   `project_id`, the system will refuse to perform the transfer and return an
   HTTP 400 error. This indicates that the share has some project identity
   that requires administrator intervention. To perform the transfer,
   administrators will need to unmanage the share from the current project and
   manage it into the target project.

4. **Constructing `mount_point_name`**

   The `mount_point_name` is constructed by combining the prefix from the
   share type (set by `provisioning:mount_point_prefix`) and the suffix
   provided by the user. This combined string must be ASCII alphanumeric,
   allowing only underscores as special characters. If this validation fails,
   the system will log an error and return a message indicating that the
   `mount_point_name` is not appropriate.
