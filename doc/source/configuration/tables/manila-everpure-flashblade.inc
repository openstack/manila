.. _manila-everpure-flashblade:

.. list-table:: Description of Everpure FlashBlade share driver configuration options
   :header-rows: 1
   :class: config-ref-table

   * - Configuration option = Default value
     - Description
   * - **[DEFAULT]**
     -
   * - ``flashblade_mgmt_vip`` = ``None``
     - (String) The name (or IP address) for the Everpure FlashBlade storage system management port.
   * - ``flashblade_data_vip`` = ``None``
     - (String) The names (or IP address) for the Everpure FlashBlade storage system data ports.
   * - ``flashblade_api`` = ``None``
     - (String) API token for an administrative level user account.
   * - ``flashblade_eradicate`` = ``True``
     - (Boolean) Enable or disable filesystem and snapshot eradication on delete.
   * - ``flashblade_ssl_cert_verify`` = ``True``
     - (Boolean) Verify the SSL certificate presented by the FlashBlade management interface. Enabled by default. Use ``flashblade_ca_cert_path`` to supply a CA bundle for self-signed or private CA certificates.
   * - ``flashblade_ca_cert_path`` = ``None``
     - (String) Path to a CA certificate bundle file (PEM) used to verify the FlashBlade management interface's SSL certificate when ``flashblade_ssl_cert_verify`` is True.
