.. _manila-infinidat:

.. list-table:: Description of INFINIDAT InfiniBox share driver configuration options
   :header-rows: 1
   :class: config-ref-table

   * - Configuration option = Default value
     - Description
   * - **[DEFAULT]**
     -
   * - ``infinibox_hostname`` = ``None``
     - (String) The name (or IP address) for the INFINIDAT Infinibox storage system.
   * - ``infinidat_use_ssl`` = ``False``
     - (Boolean) Enable SSL communication to access the INFINIDAT Infinibox storage system.
   * - ``infinidat_suppress_ssl_warnings`` = ``False``
     - (Boolean) Suppress requests library SSL certificate warnings.
   * - ``infinibox_login`` = ``None``
     - (String) Administrative user account name used to access the INFINIDAT Infinibox storage system.
   * - ``infinibox_password`` = ``None``
     - (String) Password for the administrative user account specified in the infinibox_login option.
   * - ``infinidat_pool_name`` = ``None``
     - (String) Name of the pool from which volumes are allocated.
   * - ``infinidat_nas_network_space_name`` = ``None``
     - (String) Name of the NAS network space on the INFINIDAT InfiniBox.
   * - ``infinidat_thin_provision`` = ``True``
     - (Boolean) Use thin provisioning.
   * - ``infinidat_snapdir_accessible`` = ``True``
     - (Boolean) Controls access to the ``.snapshot`` directory. By default, each share allows access to its own ``.snapshot`` directory, which contains files and directories of each snapshot taken. To restrict access to the ``.snapshot`` directory, this option should be set to ``False``.
   * - ``infinidat_snapdir_visible`` = ``False``
     - (Boolean) Controls visibility of the ``.snapshot`` directory. By default, each share contains the ``.snapshot`` directory, which is hidden on the client side. To make the ``.snapshot`` directory visible, this option should be set to ``True``.
