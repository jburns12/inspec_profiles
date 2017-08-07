
class FirewallD < Inspec::resource(1)
  ###
  #  This recourse assumes that the file sudo vim /etc/polkit-1/rules.d/49-nopasswd_global.rules has been
  #  set to allow users in group "wheel" to perform any commands without authentication.
  ###

  name 'firewalld'
  desc 'Use the firewalld resource to check and see if firewalld is configured to grand or deny access to specific hosts or services'
  example "
    describe firewalld.service_enabled_in_zone?('public','ssh') do
      it { should eq true }
    end

    describe firewalld do
      it { should be_running }
    end

    describe firewalld.running? do
      it { should eq true }
    end

    describe firewalld.port_enabled_in_zone('home', '22/tcp') do
      it { should eq false }
    end

    describe firewalld.default_zone do
      it { should eq 'public' }
    end

    describe firewalld.rule_enabled('rule family=ipv4 source address=192.168.0.14 accept') do
      it { should eq true }
    end"

  def initialize
    return skip_resource 'The `etc_hosts_deny` resource is not supported on your OS.' unless inspec.os.linux?
  end

  def exist?
    inspec.package("firewalld").installed?
  end

  def zone_exists?(query_zone)
    return false unless exist?
    result = firewalld_command("firewall-cmd --get-zones").split(" ")
    result.include?(query_zone)
  end

  def running?
    return false unless exist?
    result = firewalld_command("firewall-cmd --state")
    return result unless result == "running\n" || result == "not running\n"
    result[ 0, result.length-1 ] == "running"
  end

  def default_zone
    # return: word associated with the name of the default zone
    # example: public
    firewalld_command('firewall-cmd --get-default-zone')[ 0 .. -2 ]
  end

  def active_zones
    # return syntax:
    #   [default-zone-name]
    #       interfaces: [open interfases]
    #
    # example:
    #   public
    #       interfaces: enp0s3
    firewalld_command('firewall-cmd --get-active-zones')
  end

  def service_enabled_in_zone?(query_zone=default_zone, query_service)
    firewalld_command("firewall-cmd --zone=#{query_zone} --query-service=#{query_service}")[ 0 .. -2 ] == 'yes'
  end

  def service_ports_enabled_in_zone(query_zone=default_zone, query_service)
    # return: String of ports open, seperated by a space
    # example: 22/tcp 4722/tcp
    firewalld_command("firewall-cmd --zone=#{query_zone} --service=#{query_service} --get-ports --permanent")
  end

  def service_protocols_enabled_in_zone(query_zone=default_zone, query_service)
    # return: String of protocoals open, seperated by a space
    # example: icmp ipv4 igmp
    firewalld_command("firewall-cmd --zone=#{query_zone} --service=#{query_service} --get-protocols --permanent")
  end

  def port_enabled_in_zone?(query_zone=default_zone, query_port)
    firewalld_command("firewall-cmd --zone=#{query_zone} --query-port=#{query_port}")[ 0 .. -2 ] == 'yes'
  end

  def sources_bound(query_zone=default_zone)
    # result: a list containing either an ip address or ip address with a mask, or a ipset or an ipset with the ipset prefix.
    # example: 192.168.0.4 192.168.0.0/16 2111:DB28:ABC:12:: 2111:db89:ab3d:0112::0/64
    firewalld_command("firewall-cmd --zone=#{query_zone} --list-sources")
  end

  def services_bound(query_zone=default_zone)
    # result: a list of services bound to a zone, each seperated by a space
    # example: ssh dhcpv6-client
    firewalld_command("firewall-cmd --zone=#{query_zone} --list-services")
  end

  def rule_enabled?(rule, query_zone=default_zone)
    firewalld_command("firewall-cmd --zone=#{default_zone} --query-rich-rule='#{rule}'")[ 0 .. -2 ] == 'yes'
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
