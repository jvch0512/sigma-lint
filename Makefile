.PHONY: test sample

test:
	ruby tests/test_sigma.rb && bash tests/cli.sh

sample:
	mkdir -p docs site
	bin/sigma-lint examples > docs/sample-output.txt; true
	bin/sigma-lint examples --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "sigma-lint" "Lints Sigma detection rules for missing fields, broken conditions, undefined or unused selections, match-all values, bad ids, levels and ATT&CK tags. Ruby." "Synthetic data."
