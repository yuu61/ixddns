SHELL := sh
.DEFAULT_GOAL := validate

ENV_FILE ?= .env
-include $(ENV_FILE)

SITES_FILE ?= sites.yaml
SITE ?=

AWS ?= aws
AWS_PROFILE ?=
REGION ?= ap-northeast-1
TEMPLATE ?= .build/template.json
RULES ?= security.guard

export AWS_PROFILE REGION SITES_FILE SITE AWS

SYSTEM_PYTHON ?= $(shell command -v python3 2>/dev/null || command -v python 2>/dev/null || echo python3)

ifneq ($(wildcard .venv/Scripts/python.exe),)
PYTHON ?= .venv/Scripts/python.exe
CFN_LINT ?= .venv/Scripts/cfn-lint.exe
CFN_GUARD ?= .tools/cfn-guard-v3-x86_64-windows-latest/cfn-guard.exe
else
PYTHON ?= .venv/bin/python
CFN_LINT ?= .venv/bin/cfn-lint
CFN_GUARD ?= cfn-guard
endif

.PHONY: init venv install-dev build validate test lint guard ruff format check list deploy outputs token ix-config
.PHONY: list-sites check-sites deploy-sites outputs-sites token-sites ix-config-sites

venv:
	@if [ ! -d .venv ]; then \
		printf '%s\n' 'Creating virtual environment in .venv...'; \
		"$(SYSTEM_PYTHON)" -m venv .venv || exit 1; \
	fi

init: venv
	@$(MAKE) install-dev
	@if [ ! -f "$(ENV_FILE)" ]; then \
		cp .env.example "$(ENV_FILE)"; \
		printf '%s\n' 'Created $(ENV_FILE) from .env.example.'; \
	else \
		printf '%s\n' '$(ENV_FILE) already exists (kept).'; \
	fi
	@if [ ! -f "$(SITES_FILE)" ]; then \
		cp sites.yaml.example "$(SITES_FILE)"; \
		printf '%s\n' 'Created $(SITES_FILE) from sites.yaml.example.'; \
	else \
		printf '%s\n' '$(SITES_FILE) already exists (kept).'; \
	fi
	@printf '%s\n' 'Initialization complete. Edit $(SITES_FILE) and run "make validate".'

install-dev:
	"$(PYTHON)" -m pip install --requirement requirements-dev.txt

list:
	@"$(PYTHON)" -m scripts.sites --file "$(SITES_FILE)" list

check:
	@"$(PYTHON)" -m scripts.sites --file "$(SITES_FILE)" check $(if $(SITE),--site "$(SITE)",)

deploy: check
	@"$(PYTHON)" -m scripts.sites --file "$(SITES_FILE)" --aws "$(AWS)" deploy $(if $(SITE),--site "$(SITE)",)

outputs:
	@"$(PYTHON)" -m scripts.sites --file "$(SITES_FILE)" --aws "$(AWS)" outputs $(if $(SITE),--site "$(SITE)",)

token:
	@test -n "$(SITE)" || { printf '%s\n' 'Specify SITE=<site_id> (e.g. make token SITE=tokyo-v4).' >&2; exit 1; }
	@"$(PYTHON)" -m scripts.sites --file "$(SITES_FILE)" --aws "$(AWS)" token "$(SITE)"

ix-config:
	@"$(PYTHON)" -m scripts.sites --file "$(SITES_FILE)" --aws "$(AWS)" ix-config $(if $(SITE),--site "$(SITE)",)

validate: check test guard

test:
	"$(PYTHON)" -m unittest discover -s tests -v

build:
	@"$(PYTHON)" -m scripts.build_template --output "$(TEMPLATE)"

ruff:
	"$(PYTHON)" -m ruff check . --ignore-noqa
	"$(PYTHON)" -m ruff format --check .

format:
	"$(PYTHON)" -m ruff check . --fix --ignore-noqa
	"$(PYTHON)" -m ruff format .

lint: ruff build
	"$(CFN_LINT)" --template "$(TEMPLATE)" --regions "$(REGION)" --format json

guard: lint
	"$(CFN_GUARD)" validate --rules "$(RULES)" --data "$(TEMPLATE)" --output-format json --show-summary none

# 互換エイリアス
list-sites: list
check-sites: check
deploy-sites: deploy
outputs-sites: outputs
token-sites: token
ix-config-sites: ix-config
