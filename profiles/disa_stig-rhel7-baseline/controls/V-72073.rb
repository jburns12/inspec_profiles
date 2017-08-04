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

control "V-72073" do
  title "The file integrity tool must use FIPS 140-2 approved cryptographic hashes
for validating file contents and directories."
  desc  "File integrity tools use cryptographic hashes for verifying file contents
and directories have not been altered. These hashes must be FIPS 140-2 approved
cryptographic hashes."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72073"
  tag "rid": "SV-86697r2_rule"
  tag "stig_id": "RHEL-07-021620"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify the file integrity tool is configured to use FIPS 140-2
approved cryptographic hashes for validating file contents and directories.

Note: If RHEL-07-021350 is a finding, this is automatically a finding as the system
cannot implement FIPS 140-2 approved cryptographic algorithms and hashes.

Check to see if Advanced Intrusion Detection Environment (AIDE) is installed on the
system with the following command:

# yum list installed aide

If AIDE is not installed, ask the System Administrator how file integrity checks are
performed on the system.

If there is no application installed to perform file integrity checks, this is a
finding.

Note: AIDE is highly configurable at install time. These commands assume the
\"aide.conf\" file is under the \"/etc\" directory.

Use the following command to determine if the file is in another location:

# find / -name aide.conf

Check the \"aide.conf\" file to determine if the \"sha512\" rule has been added to
the rule list being applied to the files and directories selection lists.

An example rule that includes the \"sha512\" rule follows:

All=p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux
/bin All            # apply the custom rule to the files in bin
/sbin All          # apply the same custom rule to the files in sbin

If the \"sha512\" rule is not being used on all selection lines in the
\"/etc/aide.conf\" file, or another file integrity tool is not using FIPS 140-2
approved cryptographic hashes for validating file contents and directories, this is
a finding."
  tag "fix": "Configure the file integrity tool to use FIPS 140-2 cryptographic
hashes for validating file and directory contents.

If AIDE is installed, ensure the \"sha512\" rule is present on all file and
directory selection lists."

  # In case aide.conf is in another directory other than /etc
  # @todo - this test is redundant with V-72063.rb
  aide_conf_file = command('find / -name aide.conf').stdout.split("\n").first

  describe package("aide") do
    it { should be_installed }
  end
  describe aide_conf("#{aide_conf_file}").all_have_rule('sha512') do
    it { should eq true }
  end
end
