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

CHCON_AUDIT_FIELDS = attribute(
  'chcon_file_audit_fields',
  default: ['path=/usr/sbin/chcon', 'perm=x', 'auid>=1000', 'auid!=-1'],
  description: "The fields that you use to audit setsebool command using auditctl"
)

control "V-72139" do
  title "All uses of the chcon command must be audited."
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
  tag "gid": "V-72139"
  tag "rid": "SV-86763r3_rule"
  tag "stig_id": "RHEL-07-030580"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "cci": "CCI-002884"
  tag "nist": ["MA-4 (1) (a)", "Rev_4"]
  tag "check": "Verify the operating system generates audit records when
successful/unsuccessful attempts to use the \"chcon\" command occur.

Check the file system rule in \"/etc/audit/audit.rules\" with the following command:

# grep -i /usr/bin/chcon /etc/audit/audit.rules

-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=4294967295 -k
privileged-priv_change

If the command does not return any output, this is a finding."
  tag "fix": "Configure the operating system to generate audit records when
successful/unsuccessful attempts to use the \"chcon\" command occur.

Add or update the following rule in \"/etc/audit/rules.d/audit.rules\":

-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=4294967295 -k
privileged-priv_change

The audit daemon must be restarted for the changes to take effect."

  path = '/usr/sbin/chcon'

  describe auditd_rules2.file("#{path}") do
    its('action') { should eq ['always'] }
    its('list') { should eq ['exit'] }
    its('fields_nokey.flatten') { should match_array CHCON_AUDIT_FIELDS }
  end
end
