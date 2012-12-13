# == Define: ufw::limit
#
# Add or remove a UFW rate limiting rule.
#
# === Parameters
#
# [*ensure*]
#   Whether rule is "present" or "absent".
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
define ufw::limit(
  $ensure = 'present',
  $proto = 'tcp'
  ) {

  # Path to binaries, to shorten commands below while avoiding global search
  # path:
  $grep = '/bin/grep'
  $ufw = '/usr/sbin/ufw'

  $match = "${ufw} status | ${grep} -E \"^${name}/${proto} +LIMIT +Anywhere\""
  $cmd = "limit ${name}/${proto}"

  case $ensure {
    'present': {
      exec { "${ufw} ${cmd}":
        unless  => $match,
        require => Exec['ufw-default-deny'],
        before  => Exec['ufw-enable'],
      }
    }
    'absent': {
      exec { "${ufw} delete ${cmd}":
        onlyif  => $match,
        require => Exec['ufw-default-deny'],
        before  => Exec['ufw-enable'],
      }
    }
    default: {
      fail('Invalid value for ensure - must be absent or present.')
    }
  }
}
