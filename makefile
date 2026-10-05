SHELL := sh
.DEFAULT_GOAL := validate

ENV_FILE ?= .env
-include $(ENV_FILE)

AWS ?= aws
AWS_PROFILE ?=
REGION ?= ap-northeast-1
STACK_NAME ?= ixddns-ipv4
HOSTED_ZONE_ID ?=
RECORD_NAME ?=
RECORD_TYPE ?= A
RECORD_TTL ?= 60
LOG_RETENTION_DAYS ?= 30
ASN_RESTRICTION_ENABLED ?= false
ASN_RESTRICTION_METHOD ?= static
ASN_PREFIXES_FILE ?=
ALLOWED_ASNS ?=
IX_WAN_IF ?=
IX_SOURCE_IF ?=
IX_NOTIFY_IF ?=
IX_CONFIG_OUTPUT ?=
TEMPLATE ?= .build/template.json
RULES ?= security.guard

export AWS_PROFILE REGION STACK_NAME HOSTED_ZONE_ID RECORD_NAME
export RECORD_TYPE RECORD_TTL LOG_RETENTION_DAYS
export ASN_RESTRICTION_ENABLED ASN_RESTRICTION_METHOD ALLOWED_ASNS ASN_PREFIXES_FILE
export AWS IX_WAN_IF IX_SOURCE_IF IX_NOTIFY_IF IX_CONFIG_OUTPUT

ifneq ($(wildcard .venv/Scripts/python.exe),)
PYTHON ?= .venv/Scripts/python.exe
CFN_LINT ?= .venv/Scripts/cfn-lint.exe
CFN_GUARD ?= .tools/cfn-guard-v3-x86_64-windows-latest/cfn-guard.exe
else
PYTHON ?= .venv/bin/python
CFN_LINT ?= .venv/bin/cfn-lint
CFN_GUARD ?= cfn-guard
endif

.PHONY: install-dev build validate test lint guard ruff format check-config check-asn-config check-stack-config deploy outputs token ix-config

install-dev:
	"$(PYTHON)" -m pip install --requirement requirements-dev.txt

# 設定値は環境変数とクォート付きのシェル引数で渡します。
define aws_setup
set -eu; \
set --; \
if [ -n "$$AWS_PROFILE" ]; then set -- --profile "$$AWS_PROFILE"; else unset AWS_PROFILE; fi;
endef

check-stack-config:
	@test -n "$$REGION" || { printf '%s\n' 'Set REGION in .env.' >&2; exit 1; }
	@test -n "$$STACK_NAME" || { printf '%s\n' 'Set STACK_NAME in .env.' >&2; exit 1; }
	@command -v "$(AWS)" >/dev/null || { printf '%s\n' 'AWS CLI is not available.' >&2; exit 1; }

check-asn-config:
	@"$(PYTHON)" scripts/check_asn_config.py

check-config: check-stack-config check-asn-config
	@test -n "$$HOSTED_ZONE_ID" || { printf '%s\n' 'Set HOSTED_ZONE_ID in .env.' >&2; exit 1; }
	@test -n "$$RECORD_NAME" || { printf '%s\n' 'Set RECORD_NAME in .env.' >&2; exit 1; }

deploy: check-config validate
	@$(aws_setup) \
	allowed_asns=0; \
	if [ "$$ASN_RESTRICTION_ENABLED" = true ]; then allowed_asns="$$ALLOWED_ASNS"; fi; \
	"$(AWS)" "$$@" --region "$$REGION" --no-cli-pager cloudformation deploy \
		--stack-name "$$STACK_NAME" \
		--template-file "$(TEMPLATE)" \
		--capabilities CAPABILITY_IAM \
		--no-fail-on-empty-changeset \
		--parameter-overrides \
			"HostedZoneId=$$HOSTED_ZONE_ID" \
			"RecordName=$$RECORD_NAME" \
			"RecordType=$$RECORD_TYPE" \
			"RecordTTL=$$RECORD_TTL" \
			"LogRetentionDays=$$LOG_RETENTION_DAYS" \
			"AsnRestrictionEnabled=$$ASN_RESTRICTION_ENABLED" \
			"AsnRestrictionMethod=$$ASN_RESTRICTION_METHOD" \
			"AllowedAsns=$$allowed_asns"

outputs: check-stack-config
	@$(aws_setup) \
	"$(AWS)" "$$@" --region "$$REGION" --no-cli-pager cloudformation describe-stacks \
		--stack-name "$$STACK_NAME" --query 'Stacks[0].Outputs' --output table

token: check-stack-config
	@$(aws_setup) \
	token_arn=$$("$(AWS)" "$$@" --region "$$REGION" --no-cli-pager cloudformation describe-stacks \
		--stack-name "$$STACK_NAME" \
		--query "Stacks[0].Outputs[?OutputKey=='TokenSecretArn'].OutputValue | [0]" --output text); \
	if [ -z "$$token_arn" ] || [ "$$token_arn" = None ]; then \
		printf '%s\n' 'TokenSecretArn was not found in stack outputs.' >&2; exit 1; \
	fi; \
	"$(AWS)" "$$@" --region "$$REGION" --no-cli-pager secretsmanager get-secret-value \
		--secret-id "$$token_arn" --query SecretString --output text

ix-config: check-stack-config check-asn-config
	@"$(PYTHON)" scripts/generate_ix_config.py

validate: check-asn-config test guard

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
