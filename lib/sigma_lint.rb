# frozen_string_literal: true

require 'yaml'
require 'date'
require 'set'

# Sigma rule linter: structure, detection logic and metadata checks.
module SigmaLint
  Finding = Struct.new(:sev, :rule, :file, :where, :msg)

  RANK = { 'critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, 'info' => 4 }.freeze
  LEVELS = %w[informational low medium high critical].freeze
  STATUSES = %w[stable test experimental deprecated unsupported].freeze
  UUID = /\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/i.freeze
  ATTACK_TAG = /\Aattack\.(t\d{4}(\.\d{3})?|[a-z][a-z_-]*)\z/.freeze
  MAX_DOCS = 5000
  MAX_BYTES = 20_000_000

  def self.rank(sev) = RANK.fetch(sev, 4)

  # Splits a YAML stream into documents and loads each one safely.
  def self.load_docs(text)
    chunks = [[]]
    text.each_line do |l|
      if l =~ /\A---\s*(#.*)?\r?\n?\z/
        chunks << []
      else
        chunks.last << l
      end
    end
    raise ArgumentError, 'too many documents' if chunks.size > MAX_DOCS

    chunks.map do |c|
      body = c.join
      next nil if body.strip.empty?

      YAML.safe_load(body, permitted_classes: [Date, Time], aliases: false)
    end.compact
  end

  def self.present?(v)
    !(v.nil? || (v.respond_to?(:empty?) && v.empty?) || (v.is_a?(String) && v.strip.empty?))
  end

  # Returns the identifiers used by a condition string.
  # known: all defined selection names, used to expand wildcards and "them".
  def self.condition_refs(cond, known)
    refs = Set.new
    missing = []
    text = cond.to_s.split('|').first.to_s
    tokens = text.scan(/\(|\)|[^\s()]+/)
    i = 0
    while i < tokens.size
      t = tokens[i]
      low = t.downcase
      if %w[and or not].include?(low) || %w[( )].include?(t)
        i += 1
      elsif (low =~ /\A\d+\z/ || low == 'all') && tokens[i + 1]&.downcase == 'of' && tokens[i + 2]
        pat = tokens[i + 2]
        if pat.downcase == 'them'
          known.each { |k| refs << k }
        else
          rx = Regexp.new("\\A#{Regexp.escape(pat).gsub('\*', '.*')}\\z")
          hits = known.select { |k| k =~ rx }
          missing << pat if hits.empty?
          hits.each { |k| refs << k }
        end
        i += 3
      else
        if known.include?(t)
          refs << t
        else
          missing << t
        end
        i += 1
      end
    end
    [refs, missing]
  end

  def self.match_all?(v)
    case v
    when String then !v.empty? && v.delete('*').empty?
    when Array then !v.empty? && v.all? { |x| x.is_a?(String) && !x.empty? && x.delete('*').empty? }
    else false
    end
  end

  def self.broad_selection?(sel)
    case sel
    when Hash
      sel.any? { |k, v| !k.to_s.include?('|') && match_all?(v) } || sel.any? { |k, v| k.to_s.include?('|') && match_all?(v) && k.to_s !~ /\|(re|cidr)/ }
    when Array
      sel.any? { |x| match_all?(x) || (x.is_a?(Hash) && broad_selection?(x)) }
    else false
    end
  end

  def self.lint_rule(rule, file, idx, seen_ids)
    out = []
    unless rule.is_a?(Hash) && %w[title logsource detection].any? { |k| rule.key?(k) }
      return [Finding.new('info', 'SIG000', file, file, 'document is not a Sigma rule, ignored')]
    end
    title = rule['title'].is_a?(String) && !rule['title'].strip.empty? ? rule['title'].strip : "(untitled ##{idx})"
    where = "#{file}##{title}"
    add = ->(sev, code, msg) { out << Finding.new(sev, code, file, where, msg) }

    add.call('high', 'SIG001', 'missing title') unless present?(rule['title'])
    ls = rule['logsource']
    if !present?(ls)
      add.call('high', 'SIG001', 'missing logsource')
    elsif !ls.is_a?(Hash) || %w[category product service].none? { |k| present?(ls[k]) }
      add.call('high', 'SIG001', 'logsource has no category, product or service')
    end

    id = rule['id']
    if !present?(id)
      add.call('medium', 'SIG005', 'missing id')
    elsif !id.is_a?(String) || id !~ UUID
      add.call('medium', 'SIG005', "id #{id.inspect} is not a UUID")
    else
      key = id.downcase
      if seen_ids.key?(key) && seen_ids[key] != where
        add.call('medium', 'SIG011', "id #{id} is also used by #{seen_ids[key]}")
      else
        seen_ids[key] = where
      end
    end

    add.call('low', 'SIG007', 'missing description') unless present?(rule['description'])
    add.call('low', 'SIG007', 'missing author') unless present?(rule['author'])
    add.call('low', 'SIG012', 'missing falsepositives') unless present?(rule['falsepositives'])

    if !present?(rule['level'])
      add.call('low', 'SIG006', 'missing level')
    elsif !LEVELS.include?(rule['level'].to_s.downcase)
      add.call('medium', 'SIG008', "level #{rule['level'].inspect} is not one of #{LEVELS.join(', ')}")
    end
    if present?(rule['status']) && !STATUSES.include?(rule['status'].to_s.downcase)
      add.call('medium', 'SIG008', "status #{rule['status'].inspect} is not one of #{STATUSES.join(', ')}")
    end

    tags = rule['tags']
    if !present?(tags) || !tags.is_a?(Array)
      add.call('low', 'SIG010', 'no tags, add ATT&CK technique tags')
    else
      tags.each do |t|
        s = t.to_s
        add.call('low', 'SIG010', "tag #{s.inspect} is not a valid ATT&CK tag") if s.start_with?('attack.') && s !~ ATTACK_TAG
      end
    end

    det = rule['detection']
    if !present?(det)
      add.call('high', 'SIG001', 'missing detection')
    elsif !det.is_a?(Hash)
      add.call('high', 'SIG001', 'detection is not a mapping')
    else
      known = det.keys.map(&:to_s) - %w[condition timeframe]
      cond = det['condition']
      conds = cond.is_a?(Array) ? cond : [cond]
      if !present?(cond) || conds.none? { |c| c.is_a?(String) && !c.strip.empty? }
        add.call('high', 'SIG002', 'detection has no condition')
      else
        used = Set.new
        conds.each do |c|
          next unless c.is_a?(String)

          refs, missing = condition_refs(c, known)
          used.merge(refs)
          missing.uniq.each { |m| add.call('high', 'SIG003', "condition uses #{m.inspect} which is not defined in detection") }
        end
        (known - used.to_a).each { |k| add.call('low', 'SIG004', "selection #{k.inspect} is defined but never used in the condition") }
      end
      known.each do |k|
        add.call('medium', 'SIG009', "selection #{k.inspect} contains a value that matches everything") if broad_selection?(det[k])
      end
    end
    out
  end

  def self.audit(text, file, seen_ids = {})
    docs = begin
      load_docs(text)
    rescue Psych::Exception, ArgumentError, RangeError, TypeError, SystemStackError, EncodingError
      return [Finding.new('info', 'SIG000', file, file, 'not YAML this reader understands, ignored')]
    end
    return [Finding.new('info', 'SIG000', file, file, 'no rules found, ignored')] if docs.empty?

    docs.each_with_index.flat_map { |d, i| lint_rule(d, file, i + 1, seen_ids) }
  end

  def self.sort(findings)
    findings.sort_by { |f| [rank(f.sev), f.file, f.rule, f.where, f.msg] }
  end

  def self.files_in(path)
    if File.directory?(path)
      Dir.glob(File.join(path, '**', '*.{yml,yaml}'), File::FNM_DOTMATCH)
         .reject { |f| f.split('/').include?('.git') || !File.file?(f) || File.symlink?(f) }
         .map { |f| [f.delete_prefix(path.end_with?('/') ? path : "#{path}/"), f] }
         .sort_by(&:first)
    else
      [[File.basename(path), path]]
    end
  end

  def self.audit_path(path)
    files = files_in(path)
    seen = {}
    all = []
    files.each do |rel, full|
      text = begin
        File.size(full) <= MAX_BYTES ? File.binread(full).force_encoding('UTF-8').scrub : ''
      rescue SystemCallError
        ''
      end
      all.concat(audit(text, rel, seen))
    end
    [sort(all), files.size]
  end
end
