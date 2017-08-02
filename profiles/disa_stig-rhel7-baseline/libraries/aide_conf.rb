# encoding: utf-8
# author: Jen Burns

class AideConf < Inspec::resource(1)
  name 'aide_conf'
  desc 'Use the aide_conf InSpec audit resource to test the rules established for
    the file integrity tool AIDE. Controlled by the aide.conf file.'
  example "
  describe aide_conf().where { selection_line == '/bin' } do
    its('rules.flatten') { should include 'r' }
  end"

  attr_reader :params

  def initialize(aide_conf_path = nil)
    return skip_resource 'The `aide_conf` resource is not supported on your OS.' unless inspec.os.linux?
    @conf_path = aide_conf_path || '/etc/aide.conf'
    @files_contents = {}
    @content = nil
    @rules = nil
    read_content
    return skip_resource 'The aide_conf resource is not supported on your OS' if inspec.os.windows?
  end

  def params
    @params = parse_conf(@content)
  end

  filter = FilterTable.create
  filter.add_accessor(:where)
        .add_accessor(:entries)
        .add(:selection_lines, field: 'selection_line')
        .add(:rules,           field: 'rules')

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
    @content = filter_comments(read_file(@conf_path))
    @rules = {}
  end

  def parse_conf(content)
    content.map do |line|
      parse_line(line)
    end.compact
  end

  def parse_line(line)
    # Case when line is a rule line
    if line.include? "=" then
      selection_line = nil
      rule_list = nil
      line.gsub!(/\s+/, "")
      rule_line_arr = line.split("=")
      rules_list = rule_line_arr.last.split("+")
      rule_name = rule_line_arr.first
      @rules["#{rule_name}"] = rules_list
    end

    # Case when line is a selection line
    if line.start_with?('/') then
      selec_line_arr = line.split(" ")
      selection_line = selec_line_arr.first
      rule_list = selec_line_arr.last.split("+")
      rule_list.each_index do |i|
        hash_list = @rules["#{rule_list[i]}"]
        if hash_list != nil then
          rule_list[i] = hash_list
        end
      end
      rule_list.flatten!
    end
    {
      'selection_line' => selection_line,
      'rules' => rule_list,
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

    # If there is a file and it contains content, continue
    inspec.file(conf_path).content.lines
  end
end
