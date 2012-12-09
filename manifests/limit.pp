# == Class:
#
# Full description here.
#
# === Parameters
#
# [*proto*]
#   Protocol for firewall rule (tcp or udp).
#
# === Examples
#
# ufw::limit { 22: }
#
# === Authors
#
# Andrew Leonard
#
# === Copyright
#
# Copyright 2012 Andrew Leonard
#
define ufw::limit($proto='tcp') {

  # Path to binaries, to shorten commands below while avoiding global search
  # path:
  $grep = '/bin/grep'
  $ufw = '/usr/sbin/ufw'

  exec { "${ufw} limit ${name}/${proto}":
    unless  => "${ufw} status | ${grep} -E \"^${name}/${proto} +LIMIT +Anywhere\"",
    require => Exec['ufw-default-deny'],
    before  => Exec['ufw-enable'],
  }
}
