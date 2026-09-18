# NeonScan Makefile — vendored dependencies for offline / Termux use.

# Wheelhouse target — populated by `make bundle`.
WHEEL_DIR := vendor/wheels
LIB_DIR   := vendor/_lib

# Python interpreter used to populate vendor/_lib.
PYTHON    ?= python3

# Top-level + transitive deps we ship.
DEPS      := rich>=13.7.0

.PHONY: help bundle install-deps test clean clean-bundle run dist

help:  ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'

bundle:  ## Download wheels (rich + transitive) into vendor/wheels/
	mkdir -p $(WHEEL_DIR)
	pip download --dest $(WHEEL_DIR) $(DEPS)
	@echo "Wheels saved to $(WHEEL_DIR):"
	@ls -1 $(WHEEL_DIR)

install-bundled:  ## Install vendored wheels into a fresh vendor/_lib (no network needed)
	mkdir -p $(LIB_DIR)
	$(PYTHON) -m pip install --target $(LIB_DIR) --no-index --find-links $(WHEEL_DIR) rich
	@echo "Installed bundled deps to $(LIB_DIR)"

test:  ## Run the test suite
	$(PYTHON) -m pytest tests/ -v

offline-test:  ## Run with PYTHONPATH stripped so vendor/_lib is the only source
	@echo "Running with vendored deps only..."
	PYTHONPATH= $(PYTHON) -c "import sys, json; print(json.dumps(sys.path[:5]))"
	PYTHONPATH= $(PYTHON) neonscan.py --no-banner routes

run:  ## Run interactive neonscan
	$(PYTHON) neonscan.py

clean:  ## Clean caches and build artifacts
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache build/ dist/

clean-bundle:  ## Remove vendored wheels and pre-extracted lib
	rm -rf $(WHEEL_DIR) $(LIB_DIR)
	@echo "Cleaned bundle artifacts."
