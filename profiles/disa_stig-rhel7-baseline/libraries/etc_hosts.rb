# encoding: utf-8
# author: Matthew Dromazos

class EtcHosts < Inspec::resource(1)
  name 'etc_hosts'
  desc 'Use the etc_hosts InSpec audit resource to find an
    ip_address and its associated hosts'
  example "
  describe etc_hosts.where { ip_address == '127.0.0.1' } do
    its ( 'ip_address' ) { should eq ['127.0.0.1'] }
    its ( 'canonical_hostname' ) { should eq ['localhost'] }
    its ( 'aliases_list' ) { should eq ['localhost.localdomain localhost4 localhost4.localdomain4'] }
  end
  "

  attr_reader :params

  def initialize(host_path = nil)
    return skip_resource 'The `etc_hosts` resource is not supported on your OS.' unless inspec.os.linux? || inspec.os.windows?
    @conf_path = get_host_path_by_os(host_path)
    @files_contents = {}
    @content = nil
    @params = nil
    read_content
  end

  filter = FilterTable.create
  filter.add_accessor(:where)
        .add_accessor(:entries)
        .add(:ip_address,        field: 'ip_address')
        .add(:canonical_hostname, field: 'canonical_hostname')
        .add(:aliases_list,     field: 'aliases_list')

  filter.connect(self, :params)

  private

  def get_host_path_by_os(host_path)
    if host_path != nil
      return host_path
    elsif inspec.os.linux?
      return hosts_path || '/etc/hosts'
    elsif inspec.os.windows?
      return hosts_path || 'C:\windows\system32\drivers\etc\hosts'
    end
  end

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
    ip_address = ''
    canonical_hostname = ''
    aliases_list = ''
    # ip_address is everything up to the first space
    ip_address = line[0, line.index(' ')]
    canonical_hostname = line.partition(" ")[2].strip
    # Detect if the optional alias field is present
    if canonical_hostname.partition(' ')[0] != ""
      aliases_list = canonical_hostname.partition(' ')[2].strip
      if aliases_list.index(",") != nil
        aliases_list = aliases_list.split(',')
      end
      print aliases_list
      print "\n"
      canonical_hostname = canonical_hostname.partition(' ')[0].strip
    else
      aliases_list = ''
    end
    {
      'ip_address' => ip_address,
      'canonical_hostname' => canonical_hostname,
      'aliases_list' => aliases_list,
    }
  end

  def read_file(conf_path = @conf_path)
    file = inspec.file(conf_path)
    if !file.file?
      return skip_resource "Can't find file. \"#{@conf_path}\""
    end

    raw_conf = file.content
    if raw_conf.empty? && !file.empty?
      return skip_resource("File is empty.\"#{@conf_path}\"")
    end
    inspec.file(conf_path).content.lines
  end
end
