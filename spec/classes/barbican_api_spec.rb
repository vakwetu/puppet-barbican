require 'spec_helper'

describe 'barbican::api' do

  let :facts do
    @default_facts.merge(
      {
        :osfamily       => 'RedHat',
        :processorcount => '7',
      }
    )
  end

  let :default_params do
    {
      :verbose                  => false,
      :debug                    => false,
      :log_dir                  => '/var/log/barbican',
      :use_stderr               => true,
      :bind_host                => '0.0.0.0',
      :bind_port                => '9311',
      :log_file                 => '/var/log/barbican/api.log',
      :max_allowed_secret_in_bytes        => 10000,
      :max_allowed_request_size_in_bytes  => 1000000,
      :enable_queue                       => false,
      :queue_namespace                    => 'barbican',
      :queue_topic                        => 'barbican.workers',
      :queue_version                      => '1.1',
      :queue_server_name                  => 'barbican.queue',
      :retry_scheduler_initial_delay_seconds         => 10.0,
      :retry_scheduler_periodic_interval_max_seconds => 10.0,
      :quota_secrets                      => -1,
      :quota_orders                       => -1,
      :quota_containers                   => -1,
      :quota_consumers                    => -1,
      :quota_cas                          => -1,
      :enable_keystone_notification       => false,
      :keystone_notification_control_exchange => 'openstack',
      :keystone_notification_topic            => 'notifications',
      :keystone_notification_allow_requeue    => false,
      :keystone_notification_thread_pool_size => 10,
      :enabled_secretstore_plugins        => ['store_crypto'],
      :enabled_crypto_plugins             => ['simple_crypto'],
      :simple_crypto_plugin_kek           => 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=',
      :p11_crypto_plugin_library_path     => '/usr/lib/libCryptoki2_64.so',
      :kmip_plugin_port                   => 5696,
      :dogtag_plugin_pem_path             => '/etc/barbican/kra-agent.pem',
      :dogtag_plugin_nss_db_path          => '/etc/barbican/alias',
      :dogtag_plugin_simple_cmc_profile   => 'caOtherCert',
      :dogtag_plugin_ca_expiration_time   => 1,
      :dogtag_plugin_plugin_working_dir   => '/etc/barbican/dogtag',
      :enabled_certificate_plugins        => ['simple_certificate','snakeoil_ca'],
      :enabled_certificate_event_plugins  => ['simple_certificate'],
      :identity_uri                       => 'http://localhost:35357',
      :manage_service                     => true,
      :enabled                            => true,
    }
  end

  [{},
   {
      :verbose                            => true,
      :debug                              => true,
      :log_dir                            => '/var/log/barbican1',
      :use_stderr                         => false,
      :bind_host                          => '127.0.0.1',
      :bind_port                          => '9312',
      :log_file                           => '/var/log/barbican/api.log',
      :max_allowed_secret_in_bytes        => 20000,
      :max_allowed_request_size_in_bytes  => 2000000,
      :enable_queue                       => true,
      :quota_secrets                      => 100,
      :quota_orders                       => 100,
      :quota_containers                   => 100,
      :quota_consumers                    => 100,
      :quota_cas                          => 10,
      :enable_keystone_notification       => true,
      :keystone_notification_allow_requeue    => true,
      :keystone_notification_thread_pool_size => 20,
      :identity_uri                       => 'https://keystone.example.com:35357',
      :enabled                            => false,
    }
  ].each do |param_set|

    describe "when #{param_set == {} ? "using default" : "specifying"} class parameters" do

      let :param_hash do
        default_params.merge(param_set)
      end

      let :params do
        param_set
      end

      let :host_ref do
        "http://${::fqdn}:$param_hash[:bind_port]"
      end

      it { is_expected.to contain_class 'barbican::api::logging' }
      it { is_expected.to contain_class 'barbican::db' }

      it { is_expected.to contain_service('barbican-api').with(
        'ensure'     => (param_hash[:manage_service] && param_hash[:enabled]) ? 'running': 'stopped',
        'enable'     => param_hash[:enabled],
        'hasstatus'  => true,
        'hasrestart' => true,
        'tag'        => 'barbican-service',
      ) }

      it 'is_expected.to set default parameters' do
        [
          'verbose',
          'debug',
          'use_stderr',
          'bind_host',
          'bind_port',
          'log_dir',
          'max_allowed_secret_in_bytes',
          'max_allowed_request_size_in_bytes'
        ].each do |config|
          is_expected.to contain_barbican_config("DEFAULT/#{config}").with_value(param_hash[config.intern])
        end
      end

      it 'is_expected.to set quota parameters' do
        [
          'quota_secrets',
          'quota_orders',
          'quota_containers',
          'quota_consumers',
          'quota_cas',
        ].each do |config|
          is_expected.to contain_barbican_config("quotas/#{config}").with_value(param_hash[config.intern])
        end
      end

      it 'is_expected.to set keystone notification parameters' do
        is_expected.to contain_barbican_config('keystone_notifications/enable')\
          .with_value(param_hash[:enable_keystone_notification])
        is_expected.to contain_barbican_config('keystone_notifications/allow_requeue')\
          .with_value(param_hash[:keystone_notification_allow_requeue])
        is_expected.to contain_barbican_config('keystone_notifications/thread_pool_size')\
          .with_value(param_hash[:keystone_notification_thread_pool_size])
      end

      # TODO: enable these tests once we figure out the syntax
      #it 'is_expected.to set host_ref correctly' do
      #  is_expected.to contain_barbican_config('DEFAULT/host_href').with_value(host_ref)
      #end

      # TODO: enable these tests once we figure out the syntax
      #it 'is_expected.to add correct entry to gunicorn.conf' do
      #  should_contain_file('/etc/barbican/gunicorn-config.py')\
      #   .with_content(/\s*bind = '0.0.0.0:$param_hash[:bind_port]$/)
      #end
    end
  end

  describe 'with keystone auth' do
    let :params do
      {
        :auth_type        => 'keystone',
      }
    end

    it 'is_expected.to set keystone params correctly' do
      is_expected.to contain_barbican_api_paste_ini('pipeline:barbican_api/pipeline')\
        .with_value('keystone_authtoken context apiapp')
      is_expected.to contain_barbican_api_paste_ini('filter:keystone_authtoken/identity_uri')\
        .with_value('http://localhost:35357')
      is_expected.to contain_barbican_api_paste_ini('filter:keystone_authtoken/admin_tenant_name')\
        .with_value('services')
    end
  end

  describe 'with dogtag plugin' do
    let :params do
      {
        :enabled_crypto_plugins    => ['dogtag_crypto'],
        :dogtag_plugin_dogtag_host => 'dogtag_host',
        :dogtag_plugin_dogtag_port => 8443,
        :dogtag_plugin_nss_password => 'password123',
      }
    end

    it 'is_expected.to set dogtag parameters' do
      is_expected.to contain_barbican_config('dogtag_plugin/dogtag_host')\
        .with_value(params[:dogtag_plugin_dogtag_host])
      is_expected.to contain_barbican_config('dogtag_plugin/dogtag_port')\
        .with_value(params[:dogtag_plugin_dogtag_port])
      is_expected.to contain_barbican_config('dogtag_plugin/nss_password')\
        .with_value(params[:dogtag_plugin_nss_password])
    end 
  end

  describe 'with kmip plugin' do
    let :params do
      {
        :enabled_secretstore_plugins    => ['kmip'],
        :kmip_plugin_username      => 'kmip_user',
        :kmip_plugin_password      => 'kmip_password',
        :kmip_plugin_host          => 'kmip_host',
        :kmip_plugin_port          => 9000,
      }
    end

    it 'is_expected.to set kmip parameters' do
      is_expected.to contain_barbican_config('kmip_plugin/host')\
        .with_value(params[:kmip_plugin_host])
      is_expected.to contain_barbican_config('kmip_plugin/port')\
        .with_value(params[:kmip_plugin_port])
      is_expected.to contain_barbican_config('kmip_plugin/username')\
        .with_value(params[:kmip_plugin_username])
      is_expected.to contain_barbican_config('kmip_plugin/password')\
        .with_value(params[:kmip_plugin_password])
    end 
  end

  describe 'with pk11 plugin' do
    let :params do
      {
        :enabled_crypto_plugins         => ['p11_crypto'],
        :p11_crypto_plugin_login        => 'p11_user',
        :p11_crypto_plugin_mkek_label   => 'mkek_label',
        :p11_crypto_plugin_mkek_length  => 32,
        :p11_crypto_plugin_hmac_label   => 'hmac_label',
        :p11_crypto_plugin_slot_id      => 1,
      }
    end

    it 'is_expected.to set p11 parameters' do
      is_expected.to contain_barbican_config('p11_crypto_plugin/login') \
        .with_value(params[:p11_crypto_plugin_login])
      is_expected.to contain_barbican_config('p11_crypto_plugin/mkek_label') \
        .with_value(params[:p11_crypto_plugin_mkek_label])
      is_expected.to contain_barbican_config('p11_crypto_plugin/mkek_length') \
        .with_value(params[:p11_crypto_plugin_mkek_length])
      is_expected.to contain_barbican_config('p11_crypto_plugin/hmac_label') \
        .with_value(params[:p11_crypto_plugin_hmac_label])
      is_expected.to contain_barbican_config('p11_crypto_plugin/slot_id') \
        .with_value(params[:p11_crypto_plugin_slot_id])
    end
  end

  describe 'with disabled service managing' do
    let :params do
      {
        :manage_service => false,
        :enabled        => false,
      }
    end

    it { is_expected.to contain_service('barbican-api').with(
        'ensure'     => nil,
        'enable'     => false,
        'hasstatus'  => true,
        'hasrestart' => true,
        'tag'        => 'barbican-service',
      ) }
  end

  describe 'on RedHat platforms' do
    let :facts do
      @default_facts.merge({
        :osfamily               => 'RedHat',
        :operatingsystemrelease => '7',
      })
    end
    let(:params) { default_params }

    it { is_expected.to contain_package('barbican-api').with(
        :tag => ['openstack', 'barbican-api-package'],
    )}
  end

  describe 'on unknown platforms' do
    let :facts do
      { :osfamily => 'unknown' }
    end
    let(:params) { default_params }

    it_raises 'a Puppet::Error', /module barbican only support osfamily RedHat and Debian/
  end

end
