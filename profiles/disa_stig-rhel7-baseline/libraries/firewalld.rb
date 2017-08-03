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
require 'pry'
require 'nokogiri'
require 'ipaddr'

class FirewallD < Inspec::resource(1)
  name 'firewalld'
  desc 'Use the firewalld resource to check and see if firewalld is configured to grand or deny access to specific hosts or services'
  example "
    describe firewalld().service_enabled_in_zone('public','ssh') do
      it { should eq 'yes' }
    end

    describe firewalld().source_access('192.168.0.15', 0, 'public') do
      it { should eq 'accept' }
    end

    describe firewalld() do
      it { should be_running() }
    end

    describe firewalld().running? do
      it { should eq true }
    end

    describe firewalld().port_enabled_in_zone('home', '22/tcp') do
      it { should eq 'no' }
    end

    describe firewalld().default_zone() do
      it {should eq 'public'}
    end

    describe firewalld().rule_enabled('rule family=ipv4 source address=192.168.0.14 accept') do
      it {should eq 'yes'}
    end"

  def initialize()
    return skip_resource 'The `etc_hosts_deny` resource is not supported on your OS.' unless inspec.os.linux?
  end

  def exist?
    inspec.package("firewalld").installed?
  end

  def zone_exists?(query_zone)
    return false unless exist?
    result = firewalld_command("sudo firewall-cmd --get-zones").split(" ")
    result.include?(query_zone)
  end

  def running?
    return false unless exist?
    result = firewalld_command("sudo firewall-cmd --state")
    return result unless result == "running\n" || result == "not running\n"
    result[ 0, result.length-1 ] == "running"
  end

  def default_zone
    firewalld_command('firewall-cmd --get-default-zone')[ 0 .. -2 ]
  end

  def active_zones
    firewalld_command('firewall-cmd --get-active-zones')
  end

  def service_enabled_in_zone(query_zone=default_zone, query_service)
    firewalld_command("sudo firewall-cmd --zone=#{query_zone} --query-service=#{query_service}")[ 0 .. -2 ]
  end

  def service_ports_enabled_in_zone(query_zone=default_zone, query_service)
    firewalld_command("sudo firewall-cmd --zone=#{query_zone} -service=#{query_service} --get-ports")
  end

  def service_protocols_enabled_in_zone(query_zone=default_zone, query_service)
    firewalld_command("sudo firewall-cmd --zone=#{query_zone} --service=#{query_service} --get-protocols")
  end

  def port_enabled_in_zone(query_zone=default_zone, query_port)
    firewalld_command("sudo firewall-cmd --zone=#{query_zone} --query-port=#{query_port}")[ 0 .. -2 ]
  end

  def sources_bound(query_zone=default_zone)
    firewalld_command("sudo firewall-cmd --zone=#{query_zone} --list-sources")
  end

  def services_bound(query_zone=default_zone)
    firewalld_command("sudo firewall-cmd --zone=#{query_zone} --list-services")
  end

  def rule_enabled(rule, query_zone=default_zone)
    firewalld_command("sudo firewall-cmd --zone=#{default_zone} --query-rich-rule='#{rule}'")[ 0 .. -2 ]
  end

  private

  def firewalld_command(command)
    result = ''
    result = inspec.command(command)
    if result.stderr != ''
      return "Error on command #{command}: #{result.stderr}"
    end
    result.stdout
  end

end
