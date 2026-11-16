# frozen_string_literal: true

require 'minitest/autorun'
require_relative '../lib/sigma_lint'

class SigmaLintTest < Minitest::Test
  ID = '4a5b6c7d-1e2f-4a3b-9c8d-0e1f2a3b4c5d'

  GOOD = <<~Y
    title: Good Rule
    id: #{ID}
    status: stable
    description: d
    author: a
    tags:
      - attack.execution
      - attack.t1059.001
    logsource:
      category: process_creation
      product: windows
    detection:
      selection:
        Image|endswith: 'x.exe'
      filter:
        User: SYSTEM
      condition: selection and not filter
    falsepositives:
      - none
    level: high
  Y

  def rules(text)
    SigmaLint.audit(text, 't.yml').map(&:rule).sort
  end

  # replaces or removes a top-level line of GOOD
  def good_without(prefix)
    GOOD.lines.reject { |l| l.start_with?(prefix) }.join
  end

  def good_with(from, to)
    GOOD.sub(from, to)
  end

  def test_good_rule_is_clean
    assert_equal [], rules(GOOD)
  end

  def test_missing_title
    assert_equal ['SIG001'], rules(good_without('title:'))
  end

  def test_missing_logsource
    t = GOOD.sub(/logsource:\n  category: process_creation\n  product: windows\n/, '')
    assert_equal ['SIG001'], rules(t)
  end

  def test_logsource_without_fields
    t = GOOD.sub("category: process_creation\n  product: windows", 'definition: x')
    assert_equal ['SIG001'], rules(t)
  end

  def test_logsource_with_only_service
    t = GOOD.sub("category: process_creation\n  product: windows", 'service: sysmon')
    assert_equal [], rules(t)
  end

  def test_missing_detection
    t = GOOD.sub(/detection:.*?(?=falsepositives:)/m, '')
    assert_equal ['SIG001'], rules(t)
  end

  def test_missing_condition
    t = GOOD.sub("  condition: selection and not filter\n", '')
    assert_equal %w[SIG002], rules(t)
  end

  def test_undefined_selection
    t = GOOD.sub('selection and not filter', 'selection and not nothere')
    assert_equal %w[SIG003 SIG004], rules(t)
  end

  def test_unused_selection
    t = GOOD.sub('selection and not filter', 'selection')
    assert_equal ['SIG004'], rules(t)
  end

  def test_one_of_wildcard
    t = GOOD.sub('selection: ', 'selection: ').sub('filter:', 'selection_b:').sub('selection and not filter', '1 of selection*')
    assert_equal [], rules(t)
  end

  def test_all_of_them
    t = GOOD.sub('selection and not filter', 'all of them')
    assert_equal [], rules(t)
  end

  def test_one_of_wildcard_without_match
    t = GOOD.sub('selection and not filter', 'selection and 1 of nothing_*')
    assert_includes rules(t), 'SIG003'
  end

  def test_parentheses_and_or
    t = GOOD.sub('selection and not filter', '(selection or filter) and not (filter)')
    assert_equal [], rules(t)
  end

  def test_condition_aggregation_ignored
    t = GOOD.sub('selection and not filter', 'selection and not filter | count() by User > 5')
    assert_equal [], rules(t)
  end

  def test_condition_list
    t = GOOD.sub('condition: selection and not filter', "condition:\n      - selection\n      - filter")
    assert_equal [], rules(t)
  end

  def test_condition_not_string
    t = GOOD.sub('condition: selection and not filter', 'condition: 5')
    assert_equal ['SIG002'], rules(t).uniq.take(1) if rules(t).include?('SIG002')
    assert(rules(t).include?('SIG002'))
  end

  def test_timeframe_not_a_selection
    t = GOOD.sub('  condition:', "  timeframe: 5m\n  condition:")
    assert_equal [], rules(t)
  end

  def test_missing_id
    assert_equal ['SIG005'], rules(good_without('id:'))
  end

  def test_invalid_id
    assert_equal ['SIG005'], rules(good_with(ID, 'abc'))
  end

  def test_uppercase_uuid_ok
    assert_equal [], rules(good_with(ID, ID.upcase))
  end

  def test_missing_description
    assert_equal ['SIG007'], rules(good_without('description:'))
  end

  def test_missing_author
    assert_equal ['SIG007'], rules(good_without('author:'))
  end

  def test_missing_falsepositives
    t = GOOD.sub("falsepositives:\n  - none\n", '')
    assert_equal ['SIG012'], rules(t)
  end

  def test_missing_level
    assert_equal ['SIG006'], rules(good_without('level:'))
  end

  def test_invalid_level
    assert_equal ['SIG008'], rules(good_with('level: high', 'level: urgent'))
  end

  def test_all_levels_ok
    %w[informational low medium high critical].each do |l|
      assert_equal [], rules(good_with('level: high', "level: #{l}")), l
    end
  end

  def test_invalid_status
    assert_equal ['SIG008'], rules(good_with('status: stable', 'status: prod'))
  end

  def test_all_statuses_ok
    %w[stable test experimental deprecated unsupported].each do |s|
      assert_equal [], rules(good_with('status: stable', "status: #{s}")), s
    end
  end

  def test_missing_status_is_fine
    assert_equal [], rules(good_without('status:'))
  end

  def test_field_wildcard_is_the_exists_idiom
    t = GOOD.sub("Image|endswith: 'x.exe'", "Image: '*'")
    assert_equal [], rules(t)
    t = GOOD.sub("Image|endswith: 'x.exe'", "Image|contains: '*'")
    assert_equal [], rules(t)
  end

  def test_keyword_match_all
    t = GOOD.sub("selection:\n    Image|endswith: 'x.exe'", "selection:\n    - '*'")
    assert_equal ['SIG009'], rules(t)
  end

  def test_real_world_symbol_like_scalar_loads
    t = GOOD.sub("Image|endswith: 'x.exe'", "Image|contains:\n      - :\\ProgramData'")
    assert_equal [], rules(t)
  end

  def test_group_and_software_tags_are_valid
    t = GOOD.sub('attack.t1059.001', 'attack.g0020').sub('attack.execution', 'attack.s0508')
    assert_equal [], rules(t)
  end

  def test_wildcard_with_text_is_not_match_all
    t = GOOD.sub("Image|endswith: 'x.exe'", "Image: '*x.exe'")
    assert_equal [], rules(t)
  end

  def test_keyword_list_selection
    t = GOOD.sub("filter:\n    User: SYSTEM", "filter:\n    - '*'")
    assert_equal ['SIG009'], rules(t)
  end

  def test_no_tags
    t = GOOD.sub(/tags:.*?(?=logsource:)/m, '')
    assert_equal ['SIG010'], rules(t)
  end

  def test_bad_attack_tag
    t = GOOD.sub('attack.t1059.001', 'attack.t10599')
    assert_equal ['SIG010'], rules(t)
  end

  def test_other_tag_namespaces_ok
    t = GOOD.sub('attack.execution', 'cve.2024.1234')
    assert_equal [], rules(t)
  end

  def test_duplicate_id_across_documents
    r = SigmaLint.audit("#{GOOD}---\n#{GOOD.sub('Good Rule', 'Other Rule')}", 't.yml').map(&:rule)
    assert_equal ['SIG011'], r
  end

  def test_same_rule_twice_by_name_not_duplicate_of_itself
    seen = {}
    SigmaLint.audit(GOOD, 'a.yml', seen)
    assert_equal ['SIG011'], SigmaLint.audit(GOOD, 'b.yml', seen).map(&:rule)
  end

  def test_multi_document_where_labels
    f = SigmaLint.audit("#{good_without('title:')}---\n#{GOOD}", 't.yml').first
    assert_equal 't.yml#(untitled #1)', f.where
  end

  def test_where_has_title
    f = SigmaLint.audit(good_without('level:'), 't.yml').first
    assert_equal 't.yml#Good Rule', f.where
    assert_equal 'low', f.sev
  end

  def test_severities
    sev = ->(code, text) { SigmaLint.audit(text, 't').find { |x| x.rule == code }.sev }
    assert_equal 'high', sev.call('SIG002', GOOD.sub("  condition: selection and not filter\n", ''))
    assert_equal 'medium', sev.call('SIG005', good_without('id:'))
  end

  def test_empty_input
    assert_equal ['SIG000'], rules('')
  end

  def test_comments_only
    assert_equal ['SIG000'], rules("# nothing\n")
  end

  def test_not_yaml
    assert_equal ['SIG000'], rules("a: [unclosed\n")
  end

  def test_scalar_document
    assert_equal ['SIG000'], rules('hello')
  end

  def test_non_rule_mapping
    assert_equal ['SIG000'], rules("just: notes\n")
  end

  def test_list_document
    assert_equal ['SIG000'], rules("- a\n- b\n")
  end

  def test_alias_refused
    assert_equal ['SIG000'], rules("a: &x [1]\nb: *x\n")
  end

  def test_date_value_accepted
    assert_equal [], rules(GOOD.sub('author: a', "author: a\ndate: 2026-11-01"))
  end

  def test_wrong_types_do_not_raise
    t = "title: 5\nlogsource: x\ndetection: [1]\nlevel: [a]\ntags: x\nid: 5\n"
    SigmaLint.audit(t, 't')
    t2 = "title: x\nlogsource:\n  product: w\ndetection:\n  selection: 5\n  condition: [1, null]\n"
    SigmaLint.audit(t2, 't')
    assert true
  end

  def test_binary_input
    SigmaLint.audit("\x00\x01\xff\xfe".b.force_encoding('UTF-8'), 't')
    assert true
  end

  def test_many_documents_refused
    assert_equal ['SIG000'], rules("---\na: 1\n" * 6000)
  end

  def test_sort_order
    a = SigmaLint::Finding.new('low', 'B', 'a', 'a', '')
    b = SigmaLint::Finding.new('high', 'A', 'z', 'z', '')
    c = SigmaLint::Finding.new('high', 'A', 'a', 'a', '')
    assert_equal %w[a z a], SigmaLint.sort([a, b, c]).map(&:file)
    assert_operator SigmaLint.rank('critical'), :<, SigmaLint.rank('high')
    assert_operator SigmaLint.rank('low'), :<, SigmaLint.rank('info')
  end

  def test_fuzz_does_not_raise
    rnd = Random.new(7)
    bits = ['title: x', 'detection:', '  selection:', '    a: b', '  condition: selection', 'logsource:', '  product: w', '---', '[', ']', '{', '}', '-', ':', "'", '"', '&a', '*a', 'level: high', 'tags:', '  - attack.t1', "\n", ' ', '|', '>']
    3000.times do
      text = Array.new(rnd.rand(1..30)) { bits[rnd.rand(bits.size)] }.join(rnd.rand(2).zero? ? "\n" : ' ')
      SigmaLint.audit(text, 'f.yml')
    end
    GOOD.size.times { |i| SigmaLint.audit(GOOD[0, i], 'f.yml') }
    assert true
  end

  def test_condition_refs_direct
    refs, missing = SigmaLint.condition_refs('a and (b or not c) and 2 of x*', %w[a b x1 x2])
    assert_equal %w[a b x1 x2].sort, refs.to_a.sort
    assert_equal ['c'], missing
  end

  def test_condition_refs_case_insensitive_keywords
    refs, missing = SigmaLint.condition_refs('A AND NOT b', %w[A b])
    assert_equal 2, refs.size
    assert_empty missing
  end

  def test_audit_path_on_examples
    findings, n = SigmaLint.audit_path(File.expand_path('../examples', __dir__))
    assert_equal 3, n
    assert findings.any? { |f| f.rule == 'SIG011' }
  end
end
