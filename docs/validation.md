# Validation on real data

Counts below were produced by running the tool on public data, not on the synthetic samples in `examples/`.

## Corpus
SigmaHQ/sigma at commit `54967d6`, directory `rules/`: 3,164 rule files.

## Result
24 findings after the fixes below: 22 SIG012 and 2 SIG010, all low severity. No rule in the corpus is flagged as broken, which is the expected outcome for a curated, reviewed ruleset.

## What the real data exposed (all fixed, with regression tests)
- ATT&CK tags such as `attack.g0001` (group) and `attack.s0001` (software) were reported as unknown tactics. The tag pattern now accepts technique, group, software and tactic tags.
- A field-level wildcard such as `'*'` inside a list was treated as a match-all selection (SIG009) even when it is the normal Sigma idiom for "field exists". SIG009 now fires only for a value made purely of wildcards in a list that is the whole selection.
- Values that YAML reads as dates or symbols made `safe_load` raise. The loader now permits `Date`, `Time` and `Symbol` and still refuses aliases.

## Limits
Sigma-lint checks structure and logic hygiene. It does not run the rule against logs and does not judge detection quality.
