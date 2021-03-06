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

control "V-72141" do
  title "All uses of the restorecon command must be audited."
  desc  "
    Without generating audit records that are specific to the security and mission
needs of the organization, it would be difficult to establish, correlate, and
investigate the events relating to an incident or identify those responsible for one.

    Audit records can be generated from various components within the information
system (e.g., module or policy filter).

    Satisfies: SRG-OS-000392-GPOS-00172, SRG-OS-000463-GPOS-00207,
SRG-OS-000465-GPOS-0020.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000392-GPOS-00172"
  tag "gid": "V-72141"
  tag "rid": "SV-86765r3_rule"
  tag "stig_id": "RHEL-07-030590"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "cci": "CCI-002884"
  tag "nist": ["MA-4 (1) (a)", "Rev_4"]
  tag "subsystems": ['audit', 'auditd', 'audit_rule']
  tag "check": "Verify the operating system generates audit records when
successful/unsuccessful attempts to use the \"restorecon\" command occur.

Check the file system rule in \"/etc/audit/audit.rules\" with the following command:

# grep -i /usr/sbin/restorecon /etc/audit/audit.rules

-a always,exit -F path=/usr/sbin/restorecon -F perm=x -F auid>=1000 -F
auid!=4294967295 -k privileged-priv_change

If the command does not return any output, this is a finding."
  tag "fix": "Configure the operating system to generate audit records when
successful/unsuccessful attempts to use the \"restorecon\" command occur.

Add or update the following rule in \"/etc/audit/rules.d/audit.rules\":

-a always,exit -F path=/usr/sbin/restorecon -F perm=x -F auid>=1000 -F
auid!=4294967295 -k -F  privileged-priv_change

The audit daemon must be restarted for the changes to take effect."

  # Need to figure out a better way to do this.
  libraries = File.join(File.dirname(File.dirname(source)), 'libraries')
  eval(File.read(File.join(libraries, '/profile_helper/audit.rb')))

  check_paths('/usr/sbin/restorecon', 'x')
end
