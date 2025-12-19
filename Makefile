VENV = .venv/bin
UV_CMD = $(VENV)/uv  # Can only be used afyter dev-setup. Before that, we use `uv` from the machine.

DEFAULT: tasks


# Developer setup ##############################################################

dev-setup: clean
	@uv venv --clear
	@uv sync --locked --active --dev

pip-compile:
	@$(UV_CMD) lock --upgrade

pip-sync:
	@$(UV_CMD) sync --active --dev

# Code checks ##################################################################

check-code: check-ruff check-ty check-mypy

check-ruff:
	@$(VENV)/ruff check

check-ty:
	@$(VENV)/ty check

check-mypy:
	@$(VENV)/mypy

# Tests ########################################################################

run-tests: check-code
	@$(VENV)/pytest -p no:cacheprovider --color=yes --durations=20 --cov --cov-report=term -m "not slow"

start-fixtures:
	@./start-services.sh

stop-fixtures:
	@./stop-services.sh

# Build ########################################################################

build: clean
	@$(UV_CMD) build

deploy:
	@$(UV_CMD) publish

# Misc #########################################################################

clean: nuke-pyc
	@rm -f coverage.xml
	@rm -f junit.xml
	@rm -rf .coverage
	@rm -rf .eggs
	@rm -rf .mypy_cache
	@rm -rf .pytest_cache
	@rm -rf dist
	@rm -rf sync_roles.egg-info
	@rm -rf htmlcov

nuke-pyc:
	@find src -name '*.pyc' -exec unlink '{}' \;

tasks:
	@echo 'SETUP ⚙️'
	@echo ' ├─● dev-setup ........ Setup virtualenv and install dependencies.'
	@echo ' ├─● pip-compile ...... Upgrade the pinned dependencies.'
	@echo ' └─● pip-sync ......... Synchronize virtualenv with pinned dependencies.'
	@echo ''
	@echo 'CHECKS ✅'
	@echo ' ├─● check-code ....... Run linter and static code checks.'
	@echo ' ├─● check-ruff ....... Run ruff checks.'
	@echo ' └─● check-mypy ....... Run mypy checks.'
	@echo ''
	@echo 'TESTS 🧪'
	@echo ' ├─● run-tests ........ Run pytests tests.'
	@echo ' └─● run-fixtures ..... Start the DB fixtures needed for tests.'
	@echo ''
	@echo 'BUILD 📦'
	@echo ' └─● build ............ Build the python package.'
	@echo ''
	@echo 'DEPLOY 🚀'
	@echo ' └─● deploy ........... Deploy the python package to PyPI.'
	@echo ''
	@echo 'MISC ✨'
	@echo ' ├─● clean ............ Delete temp files'
	@echo ' └─● nuke-pyc ......... Delete all .pyc files'
