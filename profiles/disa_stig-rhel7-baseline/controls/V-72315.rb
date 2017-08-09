# encoding: utf-8
#
=begin
-----------------
Benchmark: Red Hat Enterprise Linux 7 Security Technical Implementation Guide
Status: Accepted

This Security Technical Implementation Guide is published as a tool to improve
the security of Department of Defense (DoD) information systems. The
requirements are derived from the National Institute of Standards and
Technology (NIST) 800-53 and related documents. Comments or proposed revisions
to this document should be sent via email to the following address:
disa.stig_spt@mail.mil.

Release Date: 2017-03-08
Version: 1
Publisher: DISA
Source: STIG.DOD.MIL
uri: http://iase.disa.mil
-----------------
=end

# These attributes must be updated to reflect expectations of particular system
FIREWALLD_SERVICES_ALLOW = attribute(
  'firewalld_services_allow',
  default: [
    'dhcpv6-client',
    'ssh'
  ],
  description: "Services that firewalld should be configured to allow."
)

FIREWALLD_SERVICES_DENY = attribute(
  'firewalld_services_deny',
  default: [
    'ftp',
    'telnet'
  ],
  description: "Services that firewalld should be configured to deny."
)

FIREWALLD_HOSTS_ALLOW = attribute(
  'firewalld_hosts_allow',
  default: [
    'rule family="ipv4" source address="92.188.21.1/24" accept',
    'rule family="ipv4" source address="211.17.142.46/32" accept'
  ],
  description: "Hosts that firewalld should be configured to allow."
)

FIREWALLD_HOSTS_DENY = attribute(
  'firewalld_hosts_deny',
  default: [],
  description: "Hosts that firewalld should be configured to deny."
)

FIREWALLD_PORTS_ALLOW = attribute(
  'firewalld_ports_allow',
  default: [],
  description: "Ports that firewalld should be configured to allow."
)

FIREWALLD_PORTS_DENY = attribute(
  'firewalld_ports_deny',
  default: [],
  description: "Ports that firewalld should be configured to deny."
)

TCPWRAPPERS_ALLOW = attribute(
  'tcpwrappers_allow',
  default: [
    ['sshd', 'ALL', 'allow']
  ],
  description: "Allow rules from etc/hosts.allow in form [daemon, client_list, options]."
)

TCPWRAPPERS_DENY = attribute(
  'tcpwrappers_deny',
  default: [
    ['vsftpd', 'ALL', nil]
  ],
  description: "Allow rules from etc/hosts.allow in form [daemon, client_list, options]."
)

control "V-72315" do
  title "The system access control program must be configured to grant or deny
system access to specific hosts and services."
  desc  "If the systems access control program is not configured with appropriate
rules for allowing and denying access to system network resources, services may be
accessible to unauthorized hosts."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72315"
  tag "rid": "SV-86939r1_rule"
  tag "stig_id": "RHEL-07-040810"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "If the \"firewalld\" package is not installed, ask the System
Administrator (SA) if another firewall application (such as iptables) is installed.
If an application firewall is not installed, this is a finding.

Verify the system's access control program is configured to grant or deny system
access to specific hosts.

Check to see if \"firewalld\" is active with the following command:

# systemctl status firewalld
firewalld.service - firewalld - dynamic firewall daemon
   Loaded: loaded (/usr/lib/systemd/system/firewalld.service; enabled)
   Active: active (running) since Sun 2014-04-20 14:06:46 BST; 30s ago

If \"firewalld\" is active, check to see if it is configured to grant or deny access
to specific hosts or services with the following commands:

# firewall-cmd --get-default-zone
public

# firewall-cmd --list-all --zone=public
public (default, active)
  interfaces: eth0
  sources:
  services: mdns ssh
  ports:
  masquerade: no
  forward-ports:
  icmp-blocks:
  rich rules:
  rule family=\"ipv4\" source address=\"92.188.21.1/24\" accept
  rule family=\"ipv4\" source address=\"211.17.142.46/32\" accept

If \"firewalld\" is not active, determine whether \"tcpwrappers\" is being used by
checking whether the \"hosts.allow\" and \"hosts.deny\" files are empty with the
following commands:

# ls -al /etc/hosts.allow
rw-r----- 1 root root 9 Aug  2 23:13 /etc/hosts.allow

# ls -al /etc/hosts.deny
-rw-r----- 1 root root  9 Apr  9  2007 /etc/hosts.deny

If \"firewalld\" and \"tcpwrappers\" are not installed, configured, and active, ask
the SA if another access control program (such as iptables) is installed and active.
Ask the SA to show that the running configuration grants or denies access to
specific hosts or services.

If \"firewalld\" is active and is not configured to grant access to specific hosts
and \"tcpwrappers\" is not configured to grant or deny access to specific hosts,
this is a finding."
  tag "fix": "If \"firewalld\" is installed and active on the system, configure
rules for allowing specific services and hosts.

If \"tcpwrappers\" is installed, configure the \"/etc/hosts.allow\" and
\"/etc/hosts.deny\" to allow or deny access to specific hosts."

  # @todo - take into considerations all possible options with firewalld/tcpwrappers
  if service('firewalld').running? then
    zone = command('firewall-cmd --get-default-zone').stdout.strip
    FIREWALLD_SERVICES_ALLOW.each do |service|
      describe firewalld().service_enabled_in_zone?("#{zone}", service) do
        it { should eq 'yes' }
      end
    end
    FIREWALLD_SERVICES_DENY.each do |service|
      describe firewalld().service_enabled_in_zone?("#{zone}", service) do
        it { should eq 'no' }
      end
    end
    FIREWALLD_HOSTS_ALLOW.each do |rule|
      describe firewalld().rule_enabled?(rule) do
        it { should eq 'yes' }
      end
    end
    FIREWALLD_HOSTS_DENY.each do |rule|
      describe firewalld().rule_enabled?(rule) do
        it { should eq 'no' }
      end
    end
    FIREWALLD_PORTS_ALLOW.each do |port|
      describe firewalld().port_enabled_in_zone?("#{zone}", port) do
        it { should eq 'yes' }
      end
    end
    FIREWALLD_PORTS_DENY.each do |port|
      describe firewalld().port_enabled_in_zone?("#{zone}", port) do
        it { should eq 'no' }
      end
    end

  else
    describe package('tcp_wrappers') do
      it { should be_installed }
    end
    TCPWRAPPERS_ALLOW.each do |rule|
      if rule[2] then
        describe etc_hosts_allow().where { daemon_list == rule[0] } do
          its('client_list') { should cmp [rule[1]] }
          its('options') { should cmp [rule[2]] }
        end
      else
        describe etc_hosts_allow().where { daemon_list == rule[0] } do
          its('client_list') { should cmp [rule[1]] }
          its('options') { should cmp [] }
        end
      end
    end
    TCPWRAPPERS_DENY.each do |rule|
      if rule[2] then
        describe etc_hosts_deny().where { daemon_list == rule[0] } do
          its('client_list') { should cmp [rule[1]] }
          its('options') { should cmp [rule[2]] }
        end
      else
        describe etc_hosts_deny().where { daemon_list == rule[0] } do
          its('client_list') { should cmp [rule[1]] }
          its('options') { should cmp [] }
        end
      end
    end
  end
end
