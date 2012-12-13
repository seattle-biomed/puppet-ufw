# == Define: ufw::limit
#
# Add or remove a UFW rate limiting rule.
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
# Original module by Eivind Uggedal <eivind@uggedal.com>
# Andrew Leonard
#
# === Copyright
#
# Original module Copyright (C) 2011 by Eivind Uggedal <eivind@uggedal.com>
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
