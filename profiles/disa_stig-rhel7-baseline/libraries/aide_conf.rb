# encoding: utf-8
# author: Jen Burns

class AideConf < Inspec::resource(1)
  name 'aide_conf'
  desc 'Use the aide_conf InSpec audit resource to test the rules established for
    the file integrity tool AIDE. Controlled by the aide.conf file.'
  example "
  describe aide_conf().where { selection_line == '/bin' } do
    its('rules.flatten') { should include 'r' }
  end

  describe aide_conf().all_have_rule('sha512') do
    it { should eq true }
  end
  "

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

  def all_have_rule(rule)
    in_all_lines = true
    all_lines = parse_conf(@content)
    all_lines.each do |line|
      if line['selection_line'] != nil then
        if !line['rules'].include? "#{rule}" then
          in_all_lines = false
        end
      end
    end
    in_all_lines
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
    selection_line = nil
    rule_list = nil
    # Rules that represent multiple rules (R,L,>)
    r_rules = ['p', 'i', 'l', 'n', 'u', 'g', 's', 'm', 'c', 'md5']
    l_rules = ['p', 'i', 'l', 'n', 'u', 'g']
    grow_log_rules = ['p', 'l', 'u', 'g', 'i', 'n', 'S']
    # Case when line is a rule line
    if line.include? " = " then
      line.gsub!(/\s+/, "")
      rule_line_arr = line.split("=")
      rules_list = rule_line_arr.last.split("+")
      rule_name = rule_line_arr.first
      rules_list.each_index do |i|
        # Cases where rule respresents one or more other rules
        if @rules.key?("#{rules_list[i]}") then
          rules_list[i] = @rules["#{rules_list[i]}"]
        elsif rules_list[i] == 'R' then
          rules_list[i] = r_rules
        elsif rules_list[i] == 'L' then
          rules_list[i] = l_rules
        elsif rules_list[i] == '>' then
          rules_list[i] = grow_log_rules
        end
      end
      @rules["#{rule_name}"] = rules_list.flatten
    end

    # Case when line is a selection line
    if line.start_with?('/') then
      selec_line_arr = line.split(" ")
      selection_line = selec_line_arr.first
      rule_list = selec_line_arr.last.split("+")
      rule_list.each_index do |i|
        hash_list = @rules["#{rule_list[i]}"]
        # Cases where rule respresents one or more other rules
        if hash_list != nil then
          rule_list[i] = hash_list
        elsif rule_list[i] == 'R' then
          rule_list[i] = r_rules
        elsif rule_list[i] == 'L' then
          rule_list[i] = l_rules
        elsif rule_list[i] == '>' then
          rule_list[i] = grow_log_rules
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
