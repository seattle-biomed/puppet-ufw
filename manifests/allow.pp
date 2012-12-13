# == Define: ufw::allow
#
# Add a "permit" rule using Ubuntu's Uncomplicated Firewall.
#
# === Parameters
#
# [*ensure*]
#   Whether rule is "present" or "absent".
#
# [*from*]
#   Source address for firewall rule, or "Anywhere".
#
# [*ip*]
#   Destination address for firewall rule.
#
# [*proto*]
#   Protocol (ah, esp, tcp, udp) for firewall rule.
#
# [*port*]
#   Port number for firewall rule, or "all".
#
# === Examples
#
# ufw::allow { 'allow-ssh-from-all':
#   port => 22,
# }
#
# ufw::allow { 'allow-all-from-trusted':
#  from => '10.0.0.145',
# }
#
# ufw::allow { 'allow-http-on-specific-interface':
#   port => 80,
#   ip => '10.0.0.20',
# }
#
# ufw::allow { 'allow-dns-over-udp':
#   port => 53,
#   proto => 'udp',
# }
#
# === Authors
#
# Original module by Eivind Uggedal <eivind@uggedal.com>
# Modified by Andrew Leonard
#
# === Copyright
#
# Original module Copyright (C) 2011 by Eivind Uggedal <eivind@uggedal.com>
#
define ufw::allow(
  $ensure = 'present',
  $from = 'any',
  $ip = '',
  $proto = 'tcp',
  $port = 'all'
  ) {

  # Path to binaries, to shorten commands below and avoid global search path:
  $grep = '/bin/grep'
  $ufw = '/usr/sbin/ufw'

  if $::ipaddress_eth0 != undef {
    $ipadr = $ip ? {
      ''      => $::ipaddress_eth0,
      default => $ip,
    }
  } else {
    $ipadr = 'any'
  }

  $from_match = $from ? {
    'any'   => 'Anywhere',
    default => $from,
  }

  $cmd = $port ? {
    'all'   => "allow proto ${proto} from ${from} to ${ipadr}",
    default => "allow proto ${proto} from ${from} to ${ipadr} port ${port}",
  }

  $match = "${ipadr}:${port}" ? {
    'any:all'    => "${ufw} status | ${grep} -E \" +ALLOW +${from_match}\"",
    /[0-9]:all$/ => "${ufw} status | ${grep} -E \"${ipadr}/${proto} +ALLOW +${from_match}\"",
    /^any:[0-9]/ => "${ufw} status | ${grep} -E \"${port}/${proto} +ALLOW +${from_match}\"",
    default      => "${ufw} status | ${grep} -E \"${ipadr} ${port}/${proto} +ALLOW +${from_match}\"",
  }

  case $ensure {
    'present': {
      exec { "ufw-allow-${proto}-from-${from}-to-${ipadr}-port-${port}":
        command => "${ufw} ${cmd}",
        unless  => $match,
        require => Exec['ufw-default-deny'],
        before  => Exec['ufw-enable'],
      }
    }
    'absent': {
      exec { "ufw-delete-allow-${proto}-from-${from}-to-${ipadr}-port-${port}":
        command => "${ufw} delete ${cmd}",
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
