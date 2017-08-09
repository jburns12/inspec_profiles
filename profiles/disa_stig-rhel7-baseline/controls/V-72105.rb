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

CHMOD_AUDIT_FIELDS = attribute(
  'chmod_audit_fields',
  default: [
    {"arch" => ['arch=b32', 'arch=b64'],
    "auid_pos" => 'auid>=1000',
    "auid_neg" => ['auid!=-1', 'auid!=4294967295'],
    "key" => 'key=perm_mod'},
    ['arch=b32', 'arch=b64', 'auid>=1000', 'auid!=-1', 'auid!=4294967295', 'key=perm_mod']],
  description: "The fields that you use to audit the chmod command."
)

control "V-72105" do
  title "All uses of the chmod command must be audited."
  desc  "
    Without generating audit records that are specific to the security and mission
needs of the organization, it would be difficult to establish, correlate, and
investigate the events relating to an incident or identify those responsible for one.

    Audit records can be generated from various components within the information
system (e.g., module or policy filter).

    Satisfies: SRG-OS-000458-GPOS-00203, SRG-OS-000392-GPOS-00172,
SRG-OS-000064-GPOS-0003.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000458-GPOS-00203"
  tag "gid": "V-72105"
  tag "rid": "SV-86729r2_rule"
  tag "stig_id": "RHEL-07-030410"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "Verify the operating system generates audit records when
successful/unsuccessful attempts to use the \"chmod\" command occur.

Check the file system rules in \"/etc/audit/audit.rules\" with the following command:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit
architectures. Only the lines appropriate for the system architecture must be
present.

# grep -i chmod /etc/audit/audit.rules

-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the command does not return any output, this is a finding."
  tag "fix": "Configure the operating system to generate audit records when
successful/unsuccessful attempts to use the \"chmod\" command occur.

Add or update the following rule in \"/etc/audit/rules.d/audit.rules\" (removing
those that do not match the CPU architecture):

-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=4294967295 -k perm_mod

The audit daemon must be restarted for the changes to take effect."

  sys_call = "chmod"

  # Check action and filter
  describe auditd_rules.syscall("#{sys_call}").action do
    it { should eq(["always"]) }
  end
  describe auditd_rules.syscall("#{sys_call}").action('always').list do
    it { should eq(["exit"]) }
  end

  # Check permission fields
  describe.one do
    CHMOD_AUDIT_FIELDS.first['arch'].each do |arch|
      describe auditd_rules.syscall("#{sys_call}").fields.flatten do
        it { should include arch }
      end
    end
  end
  describe auditd_rules.syscall("#{sys_call}").fields.flatten do
    it { should include CHMOD_AUDIT_FIELDS.first['auid_pos'] }
  end
  describe.one do
    CHMOD_AUDIT_FIELDS[0]['auid_neg'].each do |auid_neg|
      describe auditd_rules.syscall("#{sys_call}").fields.flatten do
        it { should include auid_neg }
      end
    end
  end
  describe auditd_rules.syscall("#{sys_call}").fields.flatten do
    it { should include CHMOD_AUDIT_FIELDS.first['key'] }
  end

  # Ensure all rule values are those that are expected
  describe auditd_rules.syscall("#{sys_call}").fields.flatten do
    it { should be_in CHMOD_AUDIT_FIELDS.last }
  end
end
