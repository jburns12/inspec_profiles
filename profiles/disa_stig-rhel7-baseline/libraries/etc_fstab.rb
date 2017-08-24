# encoding: utf-8
# author: Matthew Dromazos
require 'pry'

class EtcFstab < Inspec::resource(1)
  name 'etc_fstab'
  desc 'Use the etc_fstab InSpec audit resource to check the configuration of the etc/fstab file.'
  example "
  removable_media = etc_fstab.removable_media_file_systems
  removable_media.each do |media|
    describe media do
      its ( 'mount_options' ) { should include 'nosuid' }
    end
  end

  nfs_systems = etc_fstab.nfs_file_systems
  if removable_media != []
    nfs_systems.each do |file_system|
      describe file_system do
        its ( 'mount_options' ) { should include 'nosuid' }
        its ( 'mount_options' ) { should include 'noexec' }
        its ( 'mount_options' ) { should include '\'sec=krb5:krb5i:krb5p\'' }
      end
    end
  end

  describe etc_fstab do
    its ('home_mount_options') { should include 'nosuid' }
  end
  "

  attr_reader :params

  def initialize(fstab_path = nil)
    return skip_resource 'The `etc_fstab` resource is not supported on your OS.' unless inspec.os.linux?
    @conf_path = fstab_path || '/etc/fstab'
    @files_contents = {}
    @content = nil
    @params = nil
    read_content
    return skip_resource '`etc_fstab` is not supported on your OS' if inspec.os.windows?
  end

  filter = FilterTable.create
  filter.add_accessor(:where)
        .add_accessor(:entries)
        .add(:device_name,        field: 'device_name')
        .add(:mount_point, field: 'mount_point')
        .add(:file_system_type,     field: 'file_system_type')
        .add(:mount_options,     field: 'mount_options')
        .add(:dump_options,     field: 'dump_options')
        .add(:file_system_check_options,     field: 'file_system_check_options')

  filter.connect(self, :params)

  def removable_media_file_systems
    non_removable_media_types = ['xfs', 'ext4', 'swap', 'tmpfs']
    removable_media = where { !non_removable_media_types.include?(file_system_type) }.entries
  end

  def nfs_file_systems
    where { file_system_type.match(/nfs/) }.entries
  end

  def home_mount_options
    return "home directory not mounted" unless mounted?(point="/home")
    where { mount_point == "/home" }.entries[0].mount_options.split(",")
  end

  def mounted?(point)
    where { mount_point == point }.entries[0] != nil
  end

  def non_priv_users_mounted_dir
    inspec.passwd.where { uids >= 1000 }.homes
  end

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
    device_name, mount_point, file_system_type, mount_options = ''
    dump_options, file_system_check_options = ''

    device_name = line[0, line.index(/\s/)]

    mount_point = line.partition(/\s/)[2].strip.partition(/\s/)[0].strip

    file_system_type = line.partition(/\s/)[2].strip.partition(/\s/)[2].strip.partition(/\s/)[0].strip

    mount_options = line.partition(/\s/)[2].strip.partition(/\s/)[2].strip
      .partition(/\s/)[2].strip.partition(/\s/)[0].strip

    dump_options = line.partition(/\s/)[2].strip.partition(/\s/)[2].strip
      .partition(/\s/)[2].strip.partition(/[ \t\r\n\f]/)[2].strip.partition(/\s/)[0].strip

    file_system_check_options = line.partition(/\s/)[2].strip.partition(/\s/)[2].strip
      .partition(/\s/)[2].strip.partition(/\s/)[2].strip.partition(/\s/)[2].strip
      .partition(/\s/)[0].strip

    {
      'device_name' => device_name,
      'mount_point' => mount_point,
      'file_system_type' => file_system_type,
      'mount_options' => mount_options,
      'dump_options' => dump_options,
      'file_system_check_options' => file_system_check_options,
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
