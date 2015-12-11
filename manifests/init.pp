# == Class: barbican
#
# Full description of class barbican here.
#
# === Parameters
#
# [*ensure_package*]
#   (optional) The state of barbican packages
#   Defaults to 'present'
#
# [*verbose*]
#   (optional) Rather barbican should log at verbose level.
#   Defaults to undef.
#
# [*debug*]
#   (optional) Rather barbican should log at debug level.
#   Defaults to undef.
#
# [*use_syslog*]
#   (optional) Use syslog for logging.
#   Defaults to undef.
#
# [*use_stderr*]
#   (optional) Use stderr for logging
#   Defaults to undef.
#
# [*log_facility*]
#   (optional) Syslog facility to receive log lines.
#   Defaults to undef.
#
# [*log_file*]
#   (optional) File to write logs.
#   Defaults to undef.
#
# [*bind_host*]
#   (optional) The IP address of the network interface to listen on
#   Default to '0.0.0.0'.
#
# [*bind_port*]
#   (optional) Port that barbican binds to.
#   Defaults to '9311'
#
# [*host_href*]
#   (optional) The reference that clients use to point back to the service
#   Defaults to http://`hostname`:<bind_port>
#   TODO: needs to be set
#
# [*log_file*]
#   (optional) File to write logs.
#   Defaults to undef.
#
# [*max_allowed_secret_in_bytes*]
#   (optional) Maximum allowed secret size to be stored.
#   Defaults to 10000.
#
# [*max_allowed_request_size_in_bytes*]
#   (optional) Maximum request size against the barbican API.
#   Defaults to 1000000.
#
# [*rpc_backend*]
#   (optional) The rpc backend implementation to use, can be:
#     rabbit (for rabbitmq)
#     qpid (for qpid)
#     zmq (for zeromq)
#   Defaults to 'rabbit'
#
# [*rabbit_host*]
#   (optional) Location of rabbitmq installation.
#   Defaults to 'localhost'
#
# [*rabbit_hosts*]
#   (optional) List of clustered rabbit servers.
#   Defaults to undef
#
# [*rabbit_port*]
#   (optional) Port for rabbitmq instance.
#   Defaults to '5672'
#
# [*rabbit_password*]
#   (optional) Password used to connect to rabbitmq.
#   Defaults to 'guest'
#
# [*rabbit_userid*]
#   (optional) User used to connect to rabbitmq.
#   Defaults to 'guest'
#
# [*rabbit_virtual_host*]
#   (optional) The RabbitMQ virtual host.
#   Defaults to '/'
#
# [*rabbit_use_ssl*]
#   (optional) Connect over SSL for RabbitMQ
#   Defaults to false
#
# [*rabbit_ha_queues*]
#   (optional) Use HA queues in RabbitMQ.
#   Defaults to undef
#
# [*rabbit_heartbeat_timeout_threshold*]
#   (optional) Number of seconds after which the RabbitMQ broker is considered
#   down if the heartbeat keepalive fails.  Any value >0 enables heartbeats.
#   Heartbeating helps to ensure the TCP connection to RabbitMQ isn't silently
#   closed, resulting in missed or lost messages from the queue.
#   (Requires kombu >= 3.0.7 and amqp >= 1.4.0)
#   Defaults to 0
#
# [*rabbit_heartbeat_rate*]
#   (optional) How often during the rabbit_heartbeat_timeout_threshold period to
#   check the heartbeat on RabbitMQ connection.  (i.e. rabbit_heartbeat_rate=2
#   when rabbit_heartbeat_timeout_threshold=60, the heartbeat will be checked
#   every 30 seconds.
#   Defaults to 2
#
# [*amqp_durable_queues*]
#   (optional) Define queues as "durable" to rabbitmq.
#   Defaults to True
#
# [*enable_queue*]
#   (optional) Enable asynchronous queuing
#   Defaults to False
#
# [*queue_namespace*]
#   (optional) Namespace for the queue
#   Defaults to barbican
#
# [*queue_topic*]
#   (optional) Topic for the queue
#   Defaults to barbican.workers
#
# [*queue_version*]
#   (optional) Version for the task API
#   Defaults to 1.1
#
# [*queue_server_name*]
#   (optional) Server name for RPC service
#   Defaults to 'barbican.queue'
#
# [*retry_scheduler_initial_delay_seconds*]
#   (optional) Seconds (float) to wait before starting retry scheduler
#   Defaults to 10.0
#
# [*retry_scheduler_periodic_interval_max_seconds*]
#   (optional) Seconds (float) to wait between starting retry scheduler
#   Defaults to 10.0
#
# [*quota_secrets*]
#   (optional) default number of secrets allowed per project
#   Defaults to -1
#
# [*quota_orders*]
#   (optional) default number of orders allowed per project
#   Defaults to -1
#
# [*quota_containers*]
#   (optional) default number of containers allowed per project
#   Defaults to -1
#
# [*quota_consumers*]
#   (optional) default number of consumers allowed per project
#   Defaults to -1
#
# [*quota_cas*]
#   (optional) default number of CAs allowed per project
#   Defaults to -1
#
# [*enable_keystone_notification*]
#   (optional) Enable keystone notification listener functionality
#   Defaults to False
#
# [*keystone_notification_control_exchange*]
#   (optional) The default exchange under which topics are scoped.
#   Defaults to 'openstack'
#
# [*keystone_notification_topic*]
#   (optional) Keystone notification queue topic name.
#   Defaults to 'notifications'
#
# [*keystone_notification_allow_requeue*]
#   (optional) Requeues otification in case of notification processing error.
#   Defaults to False
#
# [*keystone_notification_thread_pool_size*]
#   (optional) max threads to be used for notification server
#   Defaults to 10
#
# [*enabled_secretstore_plugins*]
#   (optional) Enabled secretstore plugins. Multiple plugins
#   are defined in a list eg. ['store_crypto', dogtag_crypto']
#   Defaults to ['store_crypto']
#
# [*enabled_crypto_plugins*]
#   (optional) Enabled crypto_plugins.  Multiple plugins
#   are defined in a list eg. ['simple_crypto','p11_crypto']
#   Defaults to ['simple_crypto']
#
# [*simple_crypto_plugin_kek*]
#   (optional) base64 encoded 32-byte value
#   Defaults to 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY='
#
# [*p11_crypto_plugin_library_path*]
#   (optional) Path to vendor PKCS11 library
#   Defaults to '/usr/lib/libCryptoki2_64.so'
#
# [*p11_crypto_plugin_login*]
#   (optional) Password to login to PKCS11 session
#   Required if p11_crypto_plugin is enabled.
#   Defaults to undef
#
# [*p11_crypto_plugin_mkek_label*]
#   (optional) Label to identify master KEK in the HSM
#   Required if p11_crypto_plugin is enabled.
#   Defaults to undef
#
# [*p11_crypto_plugin_mkek_length*]
#   (optional) Length in bytes of master KEK
#   Required if p11_crypto_plugin is enabled.
#   Defaults to undef
#
# [*p11_crypto_plugin_hmac_label*]
#   (optional) Label to identify master KEK in the HSM
#   Required if p11_crypto_plugin is enabled.
#   Defaults to undef'
#
# [*p11_crypto_plugin_slot_id*]
#   (optional) HSM Slot id
#   Required if p11_crypto_plugin is enabled.
#   Defaults to undef
#
# [*kmip_plugin_username*]
#   (optional) username for KMIP device
#   Required if kmip_plugin is enabled.
#   Defaults to undef
#
# [*kmip_plugin_password*]
#   (optional) password for KMIP device
#   Required if kmip_plugin is enabled.
#   Defaults to undef
#
# [*kmip_plugin_host*]
#   (optional) username for KMIP device
#   Defaults to localhost
#
# [*kmip_plugin_port*]
#   (optional) port for KMIP device
#   Defaults to 5696
#
# [*kmip_plugin_keyfile*]
#   (optional) key file for KMIP device
#   Defaults to undef
#
# [*kmip_plugin_certfile*]
#   (optional) cert file for KMIP device
#   Defaults to undef
#
# [*kmip_plugin_ca_certs*]
#   (optional) ca certs file for KMIP device
#   Defaults to undef
#
# [*dogtag_plugin_pem_path*]
#   (optional) Path to KRA agent PEM file
#   Defaults to '/etc/barbican/kra-agent.pem'
#
# [*dogtag_plugin_dogtag_host*]
#   (optional) Host for the Dogtag server
#   Required if dogtag_crypto is enabled.
#   Defaults to undef 
#
# [*dogtag_plugin_dogtag_port*]
#   (optional) Host for the Dogtag server
#   Required if dogtag_crypto is enabled.
#   Defaults to undef 
#
# [*dogtag_plugin_nss_db_path*]
#   (optional) Path to plugin NSS DB
#   Defaults to '/etc/barbican/alias'
#
# [*dogtag_plugin_nss_password*]
#   (optional) Password for plugin NSS DB
#   Required if dogtag_crypto is enabled.
#   Defaults to undef 
#
# [*dogtag_plugin_simple_cmc_profile*]
#   (optional) Profile for simple CMC enrollment.
#   Defaults to 'caOtherCert'
# 
# [*dogtag_plugin_ca_expiration_time*]
#   (optional) Expiration time for the Dogtag CA entry in days
#   Defaults to 1
#
# [*dogtag_plugin_plugin_working_dir*]
#   (optional) Working directory for Dogtag plugin
#   Defaults to '/etc/barbican/dogtag'
#
# [*enabled_certificate_plugins*]
#   (optional) Enabled certificate plugins as a list.
#   e.g. ['snakeoil_ca', 'dogtag']
#   Defaults to ['simple_certificate','snakeoil_ca']
#
# [*enabled_certificate_event_plugins*]
#   (optional) Enabled certificate event plugins as a list
#   Defaults to ['simple_certificate']
#
# [*kombu_ssl_ca_certs*]
#   (optional) SSL certification authority file (valid only if SSL enabled).
#   Defaults to undef
#
# [*kombu_ssl_certfile*]
#   (optional) SSL cert file (valid only if SSL enabled).
#   Defaults to undef
#
# [*kombu_ssl_keyfile*]
#   (optional) SSL key file (valid only if SSL enabled).
#   Defaults to undef
#
# [*kombu_ssl_version*]
#   (optional) SSL version to use (valid only if SSL enabled).
#   Valid values are TLSv1, SSLv23 and SSLv3. SSLv2 may be
#   available on some distributions.
#   Defaults to 'TLSv1'
#
# [*kombu_reconnect_delay*]
#   (optional) How long to wait before reconnecting in response to an AMQP
#   consumer cancel notification.
#   Defaults to '1.0'
#
class barbican (
  $ensure_package                     = 'present',
) inherits barbican::params {
}
