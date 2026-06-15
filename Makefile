export GOCACHE ?= $(CURDIR)/.cache/go-build

.PHONY: check smoke smoke-all measure policy-list reset

check:
	bash scripts/check.sh

smoke:
	bash scripts/check.sh --smoke

smoke-all:
	SMOKE_DEVICE=all bash scripts/check.sh --smoke

measure:
	go run ./scenarios/measure

policy-list:
	go run ./scenarios/policyctl

reset:
	bash scripts/reset.sh
