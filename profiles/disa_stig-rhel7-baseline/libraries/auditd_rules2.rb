# encoding: utf-8
# copyright: 2015, Vulcano Security GmbH
# author: Christoph Hartmann
# author: Dominik Richter

require 'forwardable'
require 'utils/filter_array'

  class AuditdRulesLegacy
    def initialize(content)
      @content = content
      @opts = {
        assignment_regex: /^\s*([^:]*?)\s*:\s*(.*?)\s*$/,
        multiple_values: true,
      }
    end

    def params
      @params ||= SimpleConfig.new(@content, @opts).params
    end

    def method_missing(name)
      params[name.to_s]
    end

    def status(name)
      @status_opts = {
        assignment_regex: /^\s*([^:]*?)\s*:\s*(.*?)\s*$/,
        multiple_values: false,
      }
      @status_content ||= inspec.command('/sbin/auditctl -s').stdout.chomp
      @status_params = SimpleConfig.new(@status_content, @status_opts).params

      status = @status_params['AUDIT_STATUS']
      return nil if status.nil?

      items = Hash[status.scan(/([^=]+)=(\w*)\s*/)]
      items[name]
    end

    def to_s
      'Audit Daemon Rules (for auditd version < 2.3)'
    end
  end

  # rubocop:disable Metrics/ClassLength
  class AuditDaemonRules < Inspec.resource(1)
    extend Forwardable
    attr_accessor :rules, :lines

    name 'auditd_rules2'
    desc 'Use the auditd_rules InSpec audit resource to test the rules for logging that exist on the system. The audit.rules file is typically located under /etc/audit/ and contains the list of rules that define what is captured in log files.'
    example "
      # syntax for auditd < 2.3
      describe auditd_rules do
        its('LIST_RULES') {should contain_match(/^exit,always arch=.* key=time-change syscall=adjtimex,settimeofday/) }
        its('LIST_RULES') {should contain_match(/^exit,always arch=.* key=time-change syscall=stime,settimeofday,adjtimex/) }
        its('LIST_RULES') {should contain_match(/^exit,always arch=.* key=time-change syscall=clock_settime/)}
        its('LIST_RULES') {should contain_match(/^exit,always watch=\/etc\/localtime perm=wa key=time-change/)}
      end

      # syntax for auditd >= 2.3
      describe auditd_rules.syscall('open').action do
        it { should eq(['always']) }
      end

      describe auditd_rules.key('sshd_config') do
        its('permissions') { should contain_match(/x/) }
      end

      describe auditd_rules do
        its('lines') { should contain_match(%r{-w /etc/ssh/sshd_config/}) }
      end
    "

    def initialize
      @content = inspec.command('/sbin/auditctl -l').stdout.chomp

      if @content =~ /^LIST_RULES:/
        # do not warn on centos 5
        unless inspec.os[:name] == 'centos' && inspec.os[:release].to_i == 5
          warn '[WARN] this version of auditd is outdated. Updating it allows for using more precise matchers.'
        end
        @legacy = AuditdRulesLegacy.new(@content)
      else
        parse_content
        @legacy = nil
      end
    end

    # non-legacy instances are not asked for `its('LIST_RULES')`
    # rubocop:disable Style/MethodName
    def LIST_RULES
      return @legacy.LIST_RULES if @legacy
      raise 'Using legacy auditd_rules LIST_RULES interface with non-legacy audit package. Please use the new syntax.'
    end

    def status(name = nil)
      return @legacy.status(name) if @legacy

      @status_content ||= inspec.command('/sbin/auditctl -s').stdout.chomp
      @status_params ||= Hash[@status_content.scan(/^([^ ]+) (.*)$/)]

      return @status_params[name] if name
      @status_params
    end

    def parse_content
      @rules = {
        syscalls: [],
        files: [],
      }
      @lines = @content.lines.map(&:chomp)

      lines.each do |line|
        if is_file_syscall_syntax?(line)
          get_file_syscall_syntax_rules(line)
        end

        if is_syscall?(line)
          get_syscall_rules(line)

        elsif is_file?(line)
          get_file_rules(line)
        end
      end
    end

    def get_file_syscall_syntax_rules(line)
      file = get_file_syscall_syntax(line)
      action, list = get_action_list line
      fields, opts = get_fields line
      fields_nokey = fields.clone
      remove_keys fields_nokey
      # create a 'flatter' structure because sanity
      @rules[:files] << { file: file, list: list, action: action, fields: fields.uniq, fields_nokey: fields_nokey }.merge(opts)
    end

    def get_syscall_rules(line)
      syscalls = get_syscalls line
      action, list = get_action_list line
      fields, opts = get_fields line
      fields_nokey = fields.clone
      remove_keys fields_nokey
      # create a 'flatter' structure because sanity
      syscalls.each do |s|
        @rules[:syscalls] << { syscall: s, list: list, action: action, fields: fields.uniq, fields_nokey: fields_nokey }.merge(opts)
      end
    end

    def get_file_rules(line)
      file = get_file line
      perms = get_permissions line
      key = get_key line
      @rules[:files] << { file: file, key: key, permissions: perms }
    end

    def syscall(name)
      select_name(:syscall, name)
    end

    def file(name)
      select_name(:file, name)
    end

    # both files and syscalls have `key` identifiers
    def key(name)
      res = rules.values.flatten.find_all { |rule| rule[:key] == name }
      FilterArray.new(res)
    end

    def to_s
      'Audit Daemon Rules'
    end

    private

    def select_name(key, name)
      plural = "#{key}s".to_sym
      res = rules[plural].find_all { |rule| rule[key] == name }
      FilterArray.new(res)
    end

    def is_syscall?(line)
      line.match(/\ -S /)
    end

    def is_file?(line)
      line.match(/-w /)
    end

    def is_file_syscall_syntax?(line)
      line.match(/-F path=/)
    end

    def get_syscalls(line)
      line.scan(/-S ([^ ]+)/).flatten.first.split(',')
    end

    def get_action_list(line)
      line.scan(/-a ([^,]+),([^ ]+)/).flatten
    end

    # NB only in file lines
    def get_key(line)
      line.match(/-k ([^ ]+)/)[1] if line =~ /-k/
    end

    # NOTE there are NO precautions wrt. filenames containing spaces in auditctl
    # `auditctl -w /foo\ bar` gives the following line: `-w /foo bar -p rwxa`
    def get_file(line)
      line.match(/-w (.+) -p/)[1]
    end

    def get_file_syscall_syntax(line)
      line.match(/-F path=(\S+)\s/)[1]
    end

    def get_permissions(line)
      line.match(/-p ([^ ]+)/)[1]
    end

    def get_fields(line)
      fields = line.gsub(/-[aS] [^ ]+ /, '').split('-F ').map { |l| l.split(' ') }.flatten

      opts = {}
      fields.find_all { |x| x.match(/[a-z]+=.*/) }.each do |kv|
        k, v = kv.split('=')
        opts[k.to_sym] = v
      end

      [fields, opts]
    end

    def remove_keys(fields)
      fields.delete_if { |x| x.start_with? 'key' }
    end
  end

  class AuditDaemonRulesConf < AuditDaemonRules
    name 'auditd_rules_conf'
    desc 'Use the auditd_rules InSpec audit resource to test the rules for logging that exist on the system. The audit.rules file is typically located under /etc/audit/ and contains the list of rules that define what is captured in log files.'
    example "
    "

    include CommentParser

    def initialize(path = nil)
      @path = path || '/etc/audit/audit.rules'
      @content = read_content
      if @content =~ /^LIST_RULES:/
        # do not warn on centos 5
        unless inspec.os[:name] == 'centos' && inspec.os[:release].to_i == 5
          warn '[WARN] this version of auditd is outdated. Updating it allows for using more precise matchers.'
        end
        @legacy = AuditdRulesLegacy.new(@content)
      else
        parse_content
        @legacy = nil
      end
    end

    def to_s
      'Audit Daemon Rules found in audit.rules'
    end

    private

    def clean_conf_file
      data = inspec.file(@path).content.to_s.lines
      content = []
      data.each do |line|
        line.chomp!
        line, = parse_comment_line(line, comment_char: '#', standalone_comments: false)
        content << line unless line.empty?
      end
      content.join("\n")
    end

    def read_content
      file = inspec.file(@path)
      if !file.file?
        return skip_resource "Can't find file \"#{@path}\""
      end
      raw_conf = file.content
      if raw_conf.empty? && !file.empty?
        return skip_resource "Can't read the contents of \"#{@path}\""
      end
      clean_conf_file
    end
  end
