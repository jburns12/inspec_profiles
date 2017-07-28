# encoding: utf-8
# author: Matthew Dromazos

class EtcHostsDeny < Inspec::resource(1)
  name 'etc_hosts_deny'
  desc 'Use the etc_hosts_deny InSpec audit resource to test the connections
        the client will deny. Controlled by the /etc/hosts.deny file.'
  example "
  describe etc_hosts_deny().where { daemon_list == 'ALL' } do
    its('daemon_list') { should eq ['ALL'] }
    its('client_list') { should eq ['127.0.0.1 [::1]'] }
    its('shell_command') { should eq [''] }
  end"

  attr_reader :params

  def initialize(hosts_deny_path = nil)
    return skip_resource 'The `etc_hosts_deny` resource is not supported on your OS.' unless inspec.os.linux?
    @conf_path = hosts_deny_path || '/etc/hosts.deny'
    @files_contents = {}
    @content = nil
    @params = nil
    read_content
    return skip_resource '`etc_hosts_deny` is not supported on your OS' if inspec.os.windows?
  end

  filter = FilterTable.create
  filter.add_accessor(:where)
        .add_accessor(:entries)
        .add(:daemon_list,        field: 'daemon_list')
        .add(:client_list, field: 'client_list')
        .add(:shell_command,     field: 'shell_command')

  filter.connect(self, :params)

  private

  def filter_comments(data)
    content = []
    data.each do |line|
      line.chomp!
      content << line unless line.match(/^\s*#/) || line.empty?
    end
    content
  end

  def read_content
    @content = ''
    @params = {}
    @content = filter_comments(read_file(@conf_path))
    @params = parse_conf(@content)
  end

  def parse_conf(content)
    content.map do |line|
      parse_line(line)
    end.compact
  end

  def parse_line(line)
    daemon_list = ''
    client_list = ''
    shell_command = ''

    # If the line contains an ipv6 address, parse using a different
    # algorithm. ipv6 addresses will containt a '['
    if line.index('[') != nil
      daemon_list = line.split(':')[0].strip

      # Determines if there contains any shell commands in the line
      if line.rindex(':') > line.rindex(']')
        # First get a substring starting at the beginning and going to the
        # end of the client_list. Then get a substring containing only the client_list
        # Getting the client_list needs to be seperated into two assignments
        # because of how rubys index method works.
        client_list = line[0, line.index(':', line.rindex(']'))-1].strip
        client_list = client_list[client_list.index(':') + 1, client_list.length].strip
        # Substring starting after the client_address and goes till the end of the string.
        shell_command =  line[line.index(':', line.rindex(']'))+1, line.length].strip
      else
        # Substring starting after the first ':' till the end of the string.
        client_list = line[line.index(':') + 1, line.length].strip
        # If there is no shell commands, set to empty string.
        shell_command = ''
      end
    else
      x = line.split(':')
      daemon_list = x[0].strip
      client_list = x[1].strip
      # Determine if there contains any shell commands in the line
      if line.index(':', line.index(':')+1) != nil
        shell_command = line[line.index(':', line.index(':')+1)+1, line.length].strip
      else
        # If there is no shell commands, set to empty string.
        shell_command = ''
      end
    end
    {
      'daemon_list' => daemon_list,
      'client_list' => client_list,
      'shell_command' => shell_command,
    }
  end

  def read_file(conf_path = @conf_path)
    file = inspec.file(conf_path)
    if !file.file?
      return skip_resource "Can't find file. If this is the correct path,
        access control is turned off.\"#{@conf_path}\""
    end

    raw_conf = file.content
    if raw_conf.empty? && !file.empty?
      return skip_resource("File is empty. If this is the correct file,
        access control is turned off. Path:\"#{@conf_path}\"")
    end
    inspec.file(conf_path).content.lines
  end
end

# Unit Testing examples
#
# describe etc_hosts_deny().where { daemon_list == 'ALL' } do
#   its('daemon_list') { should eq ['ALL'] }
#   its('client_list') { should eq ['127.0.0.1 [::1]'] }
#   its('shell_command') { should eq [''] }
# end
#
# describe etc_hosts_deny().where { daemon_list == 'sshd' } do
#   its('daemon_list') { should eq ['sshd'] }
#   its('client_list') { should eq ['ALL'] }
#   its('shell_command') { should eq [''] }
# end
#
# describe etc_hosts_deny().where { daemon_list == 'LOCAL' } do
#   its('daemon_list') { should eq ['LOCAL'] }
#   its('client_list') { should eq ['[fe80::]/10'] }
#   its('shell_command') { should eq ['deny'] }
# end
