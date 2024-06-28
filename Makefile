PYTHON := $$PWD/venv/bin/python3
PYTEST := $$PWD/venv/bin/pytest
COVERAGE := $$PWD/venv/bin/coverage
TWINE := $$PWD/venv/bin/twine


test:
	flake8
	$(COVERAGE) run && $(COVERAGE) report

clean:
	rm -rf dist/* build/* deb_build/*

build: clean test
	$(PYTHON) -m build

upload-test: build
	$(TWINE) upload --repository testpypi-quickhost dist/*

upload-pypi: build
	$(TWINE) upload --repository pypi dist/*

PHONY: build test
