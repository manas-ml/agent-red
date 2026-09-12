# Northwind Outfitters red team POC
#
# Typical first run:
#   make install
#   make target          # in one terminal, then try the /chat endpoint
#   make smoke           # cheap end-to-end pipeline check
#   make scan            # the real scan
#   make report          # scorecard UI
#   make compare         # unhardened vs hardened, side by side

.DEFAULT_GOAL := help
SHELL := /bin/bash

PROMPTFOO := node_modules/.bin/promptfoo
PYTHON    := python3

.PHONY: help install target target-hardened smoke scan scan-hardened report compare test clean

help: ## Show this help
	@echo "Northwind Outfitters red team POC"
	@echo
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "  Read SAFETY.md before running the target agent."

install: ## Install Python and Node dependencies
	$(PYTHON) -m pip install -r requirements.txt
	npm install

target: ## Run the target agent on 127.0.0.1:8000 (unhardened, the default)
	AGENT_HARDENED=false $(PYTHON) -m target_agent.app

target-hardened: ## Run the target agent with every hardening control on
	AGENT_HARDENED=true $(PYTHON) -m target_agent.app

smoke: ## Cheap pipeline check: 3 plugins, 2 tests each, 1 strategy
	./scripts/run_scan.sh --smoke

scan: ## Full red team scan against the unhardened agent
	./scripts/run_scan.sh

scan-hardened: ## Full red team scan against the hardened agent
	./scripts/run_scan.sh --hardened --output output/hardened.json

report: ## Open the promptfoo scorecard UI
	$(PROMPTFOO) redteam report

compare: ## Scan unhardened, then hardened, and print the delta per plugin
	./scripts/compare_modes.sh

test: ## Run the offline self-checks (no API key, no network)
	$(PYTHON) -m pytest tests/ -q

clean: ## Remove scan output, generated probes, and logs
	rm -rf output/ logs/ redteam/redteam.yaml redteam/output/ .promptfoo/
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -prune -exec rm -rf {} + 2>/dev/null || true
	@echo "Cleaned. Note: promptfoo also keeps an eval history database in ~/.promptfoo"
