PYTHON := $$PWD/venv/bin/python3
PYTEST := $$PWD/venv/bin/pytest
COVERAGE := $$PWD/venv/bin/coverage


test:
	flake8
	$(COVERAGE) run && $(COVERAGE) report

build: test
	$(PYTHON) -m build

clean:
	rm -rf dist/* build/* deb_build/*

upload-test: build
	twine upload --repository testpypi-quickhost dist/*

rebuild-upload: clean
	$(PYTHON) -m build
	twine upload --repository testpypi-quickhost dist/*

PHONY: build test
