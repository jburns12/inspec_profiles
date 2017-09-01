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

control "V-72175" do
  title "All uses of the postdrop command must be audited."
  desc  "
    Reconstruction of harmful events or forensic analysis is not possible if audit
records do not contain enough information.

    At a minimum, the organization must audit the full-text recording of privileged
postfix commands. The organization must maintain audit trails in sufficient detail
to reconstruct events to determine the cause and impact of compromise.

    Satisfies: SRG-OS-000042-GPOS-00020, SRG-OS-000392-GPOS-0017.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000042-GPOS-00020"
  tag "gid": "V-72175"
  tag "rid": "SV-86799r3_rule"
  tag "stig_id": "RHEL-07-030760"
  tag "cci": "CCI-000135"
  tag "nist": ["AU-3 (1)", "Rev_4"]
  tag "cci": "CCI-002884"
  tag "nist": ["MA-4 (1) (a)", "Rev_4"]
  tag "check": "Verify the operating system generates audit records when
successful/unsuccessful attempts to use the \"postdrop\" command occur.

Check for the following system call being audited by performing the following
command to check the file system rules in \"/etc/audit/audit.rules\":

# grep -i /usr/sbin/postdrop /etc/audit/audit.rules

-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F
auid!=4294967295 -k privileged-postfix

If the command does not return any output, this is a finding."
  tag "fix": "Configure the operating system to generate audit records when
successful/unsuccessful attempts to use the \"postdrop\" command occur.

Add or update the following rule in \"/etc/audit/rules.d/audit.rules\":

-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F
auid!=4294967295 -k privileged-postfix

The audit daemon must be restarted for the changes to take effect."
end
