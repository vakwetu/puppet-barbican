# == Class: barbican::client
#
# Installs Barbican client.
#
# === Parameters
#
# [*ensure*]
#   (optional) Ensure state of the package.
#   Defaults to 'present'.
#
class barbican::client (
  $ensure = 'present'
) inherits barbican::params {

  package { 'python-barbicanclient':
    ensure => $ensure,
    name   => $::barbican::params::client_package_name,
    tag    => 'openstack',
  }

  if $ensure == 'present' {
    include '::openstacklib::openstackclient'
  } else {
    class { '::openstacklib::openstackclient':
      package_ensure => $ensure,
    }
  }
}
