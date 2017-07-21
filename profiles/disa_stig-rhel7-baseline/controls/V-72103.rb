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

FCHOWNAT_AUDIT_LINE_32 = attribute(
  'fchownat_audit_line_32',
  default: '^-a always,exit -F arch=b32 .*-S fchownat .*-F auid>=1000 -F auid!=4294967295 -k perm_mod',
  description: "The line that you use to audit the fchownat command on a 32-bit architecture."
)

FCHOWNAT_AUDIT_LINE_64 = attribute(
  'fchownat_audit_line_64',
  default: '^-a always,exit -F arch=b64 .*-S fchmownat .*-F auid>=1000 -F auid!=4294967295 -k perm_mod',
  description: "The line that you use to audit the fchmownat command on a 64-bit architecture."
)

control "V-72103" do
  title "All uses of the fchownat command must be audited."
  desc  "
    Without generating audit records that are specific to the security and mission
needs of the organization, it would be difficult to establish, correlate, and
investigate the events relating to an incident or identify those responsible for one.

    Audit records can be generated from various components within the information
system (e.g., module or policy filter).

    Satisfies: SRG-OS-000064-GPOS-00033, SRG-OS-000392-GPOS-00172,
SRG-OS-000458-GPOS-00203, SRG-OS-000474-GPOS-0021.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000064-GPOS-00033"
  tag "gid": "V-72103"
  tag "rid": "SV-86727r2_rule"
  tag "stig_id": "RHEL-07-030400"
  tag "cci": "CCI-000126"
  tag "nist": ["AU-2 d", "Rev_4"]
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "Verify the operating system generates audit records when
successful/unsuccessful attempts to use the \"fchownat\" command occur.

Check the file system rules in \"/etc/audit/audit.rules\" with the following
commands:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit
architectures. Only the lines appropriate for the system architecture must be
present.

# grep -i fchownat /etc/audit/audit.rules

-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the command does not return any output, this is a finding."
  tag "fix": "Add or update the following rule in \"/etc/audit/rules.d/audit.rules\"
(removing those that do not match the CPU architecture):

-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=4294967295 -k perm_mod

The audit daemon must be restarted for the changes to take effect."

  describe.one do
    describe auditd_rules do
      its('lines') { should match %r{#{FCHOWNAT_AUDIT_LINE_32}} }
    end
    describe auditd_rules do
      its('lines') { should match %r{#{FCHOWNAT_AUDIT_LINE_64}} }
    end
  end
end
