# == Class: barbican::api
#
# The barbican::api class encapsulates a Barbican API service running
# in a gunicorn container.
#
# === Parameters
#
# [*ensure_package*]
#   (optional) The state of barbican packages
#   Defaults to 'present'
#
# [*client_package_ensure*]
#   (optional) Desired ensure state of the client package.
#   accepts latest or specific versions.
#   Defaults to 'present'.
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
# [*auth_type*]
#   (optional) authentication type
#   Defaults to keystone
#
# [*identity_uri*]
#   (optional) identity server URI, needed for keystone auth
#   Defaults to http://localhost:35357
#
# [*manage_service*]
#   (optional) If Puppet should manage service startup / shutdown.
#   Defaults to true.
#
# [*enabled*]
#   (optional) Whether to enable services.
#   Defaults to true.
#
# [*database_connection*]
#   Url used to connect to database.
#   (Optional) Defaults to undef
#
# [*database_idle_timeout*]
#   Timeout when db connections should be reaped.
#   (Optional) Defaults to undef
#
# [*database_max_retries*]
#   Maximum number of database connection retries during startup.
#   Setting -1 implies an infinite retry count.
#   (Optional) Defaults to undef
#
# [*database_retry_interval*]
#   Interval between retries of opening a database connection.
#   (Optional) Defaults to undef
#
# [*database_min_pool_size*]
#   Minimum number of SQL connections to keep open in a pool.
#   (Optional) Defaults to undef
#
# [*database_max_pool_size*]
#   Maximum number of SQL connections to keep open in a pool.
#   (Optional) Defaults to undef
#
# [*database_max_overflow*]
#   If set, use this value for max_overflow with sqlalchemy.
#   (Optional) Defaults to undef
#
class barbican::api (
  $ensure_package                     = 'present',
  $client_package_ensure              = 'present',
  $verbose                            = undef,
  $debug                              = undef,
  $log_dir                            = undef,
  $log_file                           = undef,
  $use_syslog                         = undef,
  $use_stderr                         = undef,
  $log_facility                       = undef,
  $bind_host                          = '0.0.0.0',
  $bind_port                          = '9311',
  $host_href                          = undef,
  $log_file                           = undef,
  $max_allowed_secret_in_bytes        = 10000,
  $max_allowed_request_size_in_bytes  = 1000000,
  $rpc_backend                        = 'rabbit',
  $rabbit_host                        = 'localhost',
  $rabbit_hosts                       = undef,
  $rabbit_password                    = 'guest',
  $rabbit_port                        = '5672',
  $rabbit_userid                      = 'guest',
  $rabbit_virtual_host                = '/',
  $rabbit_use_ssl                     = false,
  $rabbit_heartbeat_timeout_threshold = 0,
  $rabbit_heartbeat_rate              = 2,
  $rabbit_ha_queues                   = undef,
  $amqp_durable_queues                = true,
  $enable_queue                       = false,
  $queue_namespace                    = 'barbican',
  $queue_topic                        = 'barbican.workers',
  $queue_version                      = '1.1',
  $queue_server_name                    = 'barbican.queue',
  $retry_scheduler_initial_delay_seconds = 10.0,
  $retry_scheduler_periodic_interval_max_seconds = 10.0,
  $quota_secrets                      = -1,
  $quota_orders                       = -1,
  $quota_containers                   = -1,
  $quota_consumers                    = -1,
  $quota_cas                          = -1,
  $enable_keystone_notification       = false,
  $keystone_notification_control_exchange = 'openstack',
  $keystone_notification_topic        = 'notifications',
  $keystone_notification_allow_requeue = false,
  $keystone_notification_thread_pool_size = 10,
  $enabled_secretstore_plugins        = ['store_crypto'],
  $enabled_crypto_plugins             = ['simple_crypto'],
  $simple_crypto_plugin_kek           = 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=',
  $p11_crypto_plugin_library_path     = '/usr/lib/libCryptoki2_64.so',
  $p11_crypto_plugin_login            = undef,
  $p11_crypto_plugin_mkek_label       = undef,
  $p11_crypto_plugin_mkek_length      = undef,
  $p11_crypto_plugin_hmac_label       = undef,
  $p11_crypto_plugin_slot_id          = undef,
  $kmip_plugin_username               = undef,
  $kmip_plugin_password               = undef,
  $kmip_plugin_host                   = undef,
  $kmip_plugin_port                   = 5696,
  $kmip_plugin_keyfile                = undef,
  $kmip_plugin_certfile               = undef,
  $kmip_plugin_ca_certs               = undef,
  $dogtag_plugin_pem_path             = '/etc/barbican/kra-agent.pem',
  $dogtag_plugin_dogtag_host          = undef,
  $dogtag_plugin_dogtag_port          = undef,
  $dogtag_plugin_nss_db_path          = '/etc/barbican/alias',
  $dogtag_plugin_nss_password         = undef,
  $dogtag_plugin_simple_cmc_profile   = 'caOtherCert',
  $dogtag_plugin_ca_expiration_time   = 1,
  $dogtag_plugin_plugin_working_dir   = '/etc/barbican/dogtag',
  $enabled_certificate_plugins        = ['simple_certificate','snakeoil_ca'],
  $enabled_certificate_event_plugins  = ['simple_certificate'],
  $kombu_ssl_ca_certs                 = undef,
  $kombu_ssl_certfile                 = undef,
  $kombu_ssl_keyfile                  = undef,
  $kombu_ssl_version                  = 'TLSv1',
  $kombu_reconnect_delay              = '1.0',
  $auth_type                          = undef,
  $identity_uri                       = 'http://localhost:35357',
  $manage_service                     = true,
  $enabled                            = true,
  $database_connection                = undef,
  $database_idle_timeout              = undef,
  $database_min_pool_size             = undef,
  $database_max_pool_size             = undef,
  $database_max_retries               = undef,
  $database_retry_interval            = undef,
  $database_max_overflow              = undef,

) inherits barbican::params {

  
  include ::barbican::db
  include ::barbican::api::logging
  require keystone::python

  if $kombu_ssl_ca_certs and !$rabbit_use_ssl {
    fail('The kombu_ssl_ca_certs parameter requires rabbit_use_ssl to be set to true')
  }
  if $kombu_ssl_certfile and !$rabbit_use_ssl {
    fail('The kombu_ssl_certfile parameter requires rabbit_use_ssl to be set to true')
  }
  if $kombu_ssl_keyfile and !$rabbit_use_ssl {
    fail('The kombu_ssl_keyfile parameter requires rabbit_use_ssl to be set to true')
  }
  if ($kombu_ssl_certfile and !$kombu_ssl_keyfile) or ($kombu_ssl_keyfile and !$kombu_ssl_certfile) {
    fail('The kombu_ssl_certfile and kombu_ssl_keyfile parameters must be used together')
  }

  # p11 crypto plugin
  if 'p11_crypto' in $enabled_crypto_plugins {
    if $p11_crypto_plugin_login == undef {
        fail("p11_crypto_plugin_login must be defined")
    }
    if $p11_crypto_plugin_mkek_label == undef {
        fail("p11_crypto_plugin_mkek_label must be defined")
    }
    if $p11_crypto_plugin_mkek_length == undef {
        fail("p11_crypto_plugin_mkek_length must be defined")
    }
    if $p11_crypto_plugin_hmac_label == undef {
        fail("p11_crypto_plugin_hmac_label must be defined")
    }
    if $p11_crypto_plugin_slot_id == undef {
        fail("p11_crypto_plugin_slot_id must be defined")
    }
  }

  # kmip secretstore plugin
  if 'kmip' in $enabled_secretstore_plugins {
    if $kmip_plugin_host == undef {
      fail("kmip_plugin_host must be defined")
    }
    if $kmip_plugin_port == undef {
      fail("kmip_plugin_port must be defined")
    }
    if $kmip_plugin_username != undef {
      if $kmip_plugin_password == undef {
        fail("kmip_plugin_password must be defined if kmip_plugin_username is defined")
      }
    } else {
      if $kmip_plugin_certfile == undef {
        fail("kmip_plugin_certfile must be defined")
      }
      if $kmip_plugin_keyfile == undef {
        fail("kmip_plugin_keyfile must be defined")
      }
      if $kmip_plugin_ca_certs == undef {
        fail("kmip_plugin_ca_certs must be defined")
      }
    }
  }

  #dogtag plugin
  if (('dogtag_crypto' in $enabled_crypto_plugins) or
      ('dogtag' in $enabled_certificate_plugins)) {
    if $dogtag_plugin_dogtag_host == undef {
      fail("dogtag_plugin_dogtag_host must be defined")
    }
    if $dogtag_plugin_dogtag_port == undef {
      fail("dogtag_plugin_dogtag_port must be defined")
    }
    if $dogtag_plugin_nss_password == undef {
      fail("dogtag_plugin_nss_password must be defined")
    }
    package {'dogtag-client':
      ensure => $ensure_package,
      name   => $::barbican::params::dogtag_client_package,
      tag    => ['openstack', 'dogtag-client-package']
    } -> Service['barbican-api'] 
  }

  group { 'barbican':
    ensure  => present,
    system  => true,
    require => Package['barbican-api'],
  }

  user { 'barbican':
    ensure  => 'present',
    gid     => 'barbican',
    system  => true,
    require => Package['barbican-api'],
  }

  file { ['/etc/barbican', '/var/log/barbican', '/var/lib/barbican']:
    ensure  => directory,
    mode    => '0770',
    owner   => 'root',
    group   => 'barbican',
    require => Package['barbican-api'],
    notify  => Service['barbican-api'],
  }

  file { ['/etc/barbican/barbican.conf',
          '/etc/barbican/barbican-api-paste.ini',
          '/etc/barbican/gunicorn-config.py']:
    ensure  => present,
    mode    => '0600',
    owner   => 'barbican',
    group   => 'barbican',
    require => Package['barbican-api'],
    notify  => Service['barbican-api'],
  }

  package { 'barbican-api':
    ensure => $ensure_package,
    name   => $::barbican::params::api_package_name,
    tag    => ['openstack', 'barbican-api-package'],
  }

  if $client_package_ensure == 'present' {
    include '::barbican::client'
  } else {
    class { '::barbican::client':
      ensure => $client_package_ensure,
    }
  }

  File['/etc/barbican/barbican.conf'] -> Barbican_config<||>
  File['/etc/barbican/barbican-api-paste.ini'] -> Barbican_api_paste_ini<||>

  Barbican_config<||>   ~> Service['barbican-api']
  Barbican_api_paste_ini<||>   ~> Service['barbican-api']

  # basic service config
  if $host_href == undef {
    $host_href_real = "http://${::fqdn}:${bind_port}"
  } else {
    $host_href_real = $host_href
  }

  barbican_config {
    'DEFAULT/bind_host': value => $bind_host;
    'DEFAULT/bind_port': value => $bind_port;
    'DEFAULT/host_href': value => $host_href_real;
  }

  File['/etc/barbican/gunicorn-config.py'] ->
    file_line { 'Modify bind_port in gunicorn-config.py':
      path => '/etc/barbican/gunicorn-config.py',
      line => "bind = '${bind_host}:${bind_port}'",
      match => ".*bind = .*",
    } -> Service['barbican-api']

  #rabbit config
  if $rpc_backend == 'rabbit' {
    barbican_config {
      'oslo_messaging_rabbit/rabbit_password':              value => $rabbit_password, secret => true;
      'oslo_messaging_rabbit/rabbit_userid':                value => $rabbit_userid;
      'oslo_messaging_rabbit/rabbit_virtual_host':          value => $rabbit_virtual_host;
      'oslo_messaging_rabbit/rabbit_use_ssl':               value => $rabbit_use_ssl;
      'oslo_messaging_rabbit/heartbeat_timeout_threshold':  value => $rabbit_heartbeat_timeout_threshold;
      'oslo_messaging_rabbit/heartbeat_rate':               value => $rabbit_heartbeat_rate;
      'oslo_messaging_rabbit/kombu_reconnect_delay':        value => $kombu_reconnect_delay;
      'DEFAULT/amqp_durable_queues':                        value => $amqp_durable_queues;
    }

    if $rabbit_use_ssl {

      if $kombu_ssl_ca_certs {
        barbican_config { 'oslo_messaging_rabbit/kombu_ssl_ca_certs': value => $kombu_ssl_ca_certs; }
      } else {
        barbican_config { 'oslo_messaging_rabbit/kombu_ssl_ca_certs': ensure => absent; }
      }

      if $kombu_ssl_certfile or $kombu_ssl_keyfile {
        barbican_config {
          'oslo_messaging_rabbit/kombu_ssl_certfile': value => $kombu_ssl_certfile;
          'oslo_messaging_rabbit/kombu_ssl_keyfile':  value => $kombu_ssl_keyfile;
        }
      } else {
        barbican_config {
          'oslo_messaging_rabbit/kombu_ssl_certfile': ensure => absent;
          'oslo_messaging_rabbit/kombu_ssl_keyfile':  ensure => absent;
        }
      }

      if $kombu_ssl_version {
        barbican_config { 'oslo_messaging_rabbit/kombu_ssl_version':  value => $kombu_ssl_version; }
      } else {
        barbican_config { 'oslo_messaging_rabbit/kombu_ssl_version':  ensure => absent; }
      }

    } else {
      barbican_config {
        'oslo_messaging_rabbit/kombu_ssl_ca_certs': ensure => absent;
        'oslo_messaging_rabbit/kombu_ssl_certfile': ensure => absent;
        'oslo_messaging_rabbit/kombu_ssl_keyfile':  ensure => absent;
        'oslo_messaging_rabbit/kombu_ssl_version':  ensure => absent;
      }
    }

    if $rabbit_hosts {
      barbican_config { 'oslo_messaging_rabbit/rabbit_hosts': value => join($rabbit_hosts, ',') }
    } else {
      barbican_config { 'oslo_messaging_rabbit/rabbit_host':  value => $rabbit_host }
      barbican_config { 'oslo_messaging_rabbit/rabbit_port':  value => $rabbit_port }
      barbican_config { 'oslo_messaging_rabbit/rabbit_hosts': value => "${rabbit_host}:${rabbit_port}" }
    }

    if $rabbit_ha_queues == undef {
      if $rabbit_hosts {
        barbican_config { 'oslo_messaging_rabbit/rabbit_ha_queues': value => true }
      } else {
        barbican_config { 'oslo_messaging_rabbit/rabbit_ha_queues': value => false }
      }
    } else {
      barbican_config { 'oslo_messaging_rabbit/rabbit_ha_queues': value => $rabbit_ha_queues }
    }
  }

  # queue options
  barbican_config {
    'queue/enable':    value =>  $enable_queue;
    'queue/namespace': value => $queue_namespace;
    'queue/topic':     value => $queue_topic;
    'queue/version':   value => $queue_version;
    'queue/server_name': value => $queue_server_name;
  }

  # retry scheduler options
  barbican_config {
    'retry_scheduler/initial_delay_seconds':         value => $retry_scheduler_initial_delay_seconds;
    'retry_scheduler/periodic_interval_max_seconds': value => $retry_scheduler_periodic_interval_max_seconds;
  }

  # max allowed secret options
  barbican_config {
    'DEFAULT/max_allowed_secret_in_bytes': value => $max_allowed_secret_in_bytes;
    'DEFAULT/max_allowed_request_size_in_bytes': value => $max_allowed_request_size_in_bytes;
  }
  # quota options
  barbican_config {
    'quotas/quota_secrets':      value => $quota_secrets;
    'quotas/quota_orders':       value => $quota_orders;
    'quotas/quota_containers':   value => $quota_containers;
    'quotas/quota_consumers':    value => $quota_consumers;
    'quotas/quota_cas':          value => $quota_cas;
  }

  # keystone notification options
  barbican_config {
     'keystone_notifications/enable':           value => $enable_keystone_notification;
     'keystone_notifications/control_exchange': value => $keystone_notification_control_exchange;
     'keystone_notifications/topic':            value => $keystone_notification_topic;
     'keystone_notifications/allow_requeue':    value => $keystone_notification_allow_requeue;
     'keystone_notifications/thread_pool_size': value => $keystone_notification_thread_pool_size;
  }

  # TODO - add this when support for multicfg is added
  # enabled_secretstore_plugins - how to do multiple choices?
  #$enabled_secretstore_plugins.each do |plugin|
  #  barbican_config {
  #      'secretstore/enabled_secretstore_plugins': value => plugin
  #  }
  #end

  # enabled_certificate_plugins - how to do multiple choices?
  #$enabled_certificate_plugins.each do |plugin|
  #  barbican_config {
  #      'certificate/enabled_certificate_plugins': value => plugin
  #  }
  #end

  # enabled_crypto_plugins - how to do multiple choices?
  #$enabled_crypto_plugins.each do |plugin|
  #  barbican_config {
  #      'crypto/enabled_crypto_plugins': value => plugin
  #  }
  #end

  # enabled_certificate_event_plugins - how to do multiple choices?
  #$enabled_certificate_event_plugins.each do |plugin|
  #  barbican_config {
  #      'certificate_event/enabled_certificate_event_plugins': value => plugin
  # }
  #end

  # simple crypto plugin
  #if 'simple_crypto' in $enabled_crypto_plugins {
  #  barbican_config {'simple_crypto_plugin/kek': value => $simple_crypto_plugin_kek }
  #}

  # p11 crypto plugin
  if 'p11_crypto' in $enabled_crypto_plugins {
    barbican_config {
      'p11_crypto_plugin/library_path':   value => $p11_crypto_plugin_library_path;
      'p11_crypto_plugin/login':          value => $p11_crypto_plugin_login;
      'p11_crypto_plugin/mkek_label':     value => $p11_crypto_plugin_mkek_label;
      'p11_crypto_plugin/mkek_length':    value => $p11_crypto_plugin_mkek_length;
      'p11_crypto_plugin/hmac_label':     value => $p11_crypto_plugin_hmac_label;
      'p11_crypto_plugin/slot_id':        value => $p11_crypto_plugin_slot_id;
    }
  }

  # kmip secretstore plugin
  if 'kmip' in $enabled_secretstore_plugins {
    if $kmip_plugin_username != undef {
      barbican_config {
        'kmip_plugin/username': value => $kmip_plugin_username;
        'kmip_plugin/password': value => $kmip_plugin_password;
        'kmip_plugin/host':     value => $kmip_plugin_host;
        'kmip_plugin/port':     value => $kmip_plugin_port;
      }
    } else {
      barbican_config {
        'kmip_plugin/keyfile':  value => $kmip_plugin_keyfile;
        'kmip_plugin/certfile': value => $kmip_plugin_certfile;
        'kmip_plugin/ca_certs': value => $kmip_plugin_ca_certs;
        'kmip_plugin/host':     value => $kmip_plugin_host;
        'kmip_plugin/port':     value => $kmip_plugin_port;
      }
    }
  }

  #dogtag plugin
  if (('dogtag_crypto' in $enabled_crypto_plugins) or
      ('dogtag' in $enabled_certificate_plugins)) {
    barbican_config {
      'dogtag_plugin/pem_path':     value => $dogtag_plugin_pem_path;
      'dogtag_plugin/dogtag_host':  value => $dogtag_plugin_dogtag_host;
      'dogtag_plugin/dogtag_port':  value => $dogtag_plugin_dogtag_port;
      'dogtag_plugin/nss_db_path':  value => $dogtag_plugin_nss_db_path;
      'dogtag_plugin/nss_password': value => $dogtag_plugin_nss_password;
      'dogtag_plugin/simple_cmc_profile': value => $dogtag_plugin_simple_cmc_profile;
      'dogtag_plugin/ca_expiration_time': value => $dogtag_plugin_ca_expiration_time;
      'dogtag_plugin/plugin_working_dir': value => $dogtag_plugin_plugin_working_dir;
    }
  }

  # keystone config
  if $auth_type == 'keystone' {
    barbican_api_paste_ini {
      'pipeline:barbican_api/pipeline': value => 'keystone_authtoken context apiapp';
      'filter:keystone_authtoken/identity_uri': value => $identity_uri;
      'filter:keystone_authtoken/admin_tenant_name': value => 'services';
    }
  }
 
  if $manage_service {
    if $enabled {
      $service_ensure = 'running'
    } else {
      $service_ensure = 'stopped'
    }
  }

  service { 'barbican-api':
    ensure     => $service_ensure,
    name       => $::barbican::params::api_service_name,
    enable     => $enabled,
    hasstatus  => true,
    hasrestart => true,
    tag        => 'barbican-service',
  }

  if $validate {
    $defaults = {
      'barbican-api' => {
        'command'  => "barbican --os-auth-url ${auth_url} --os-tenant-name ${keystone_tenant} --os-username ${keystone_user} --os-password ${keystone_password} secret-list",
      }
    }
    $validation_options_hash = merge ($defaults, $validation_options)
    create_resources('openstacklib::service_validation', $validation_options_hash, {'subscribe' => 'Service[barbican-api]'})
  }

}
