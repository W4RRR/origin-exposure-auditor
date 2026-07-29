.PHONY: install test coverage lint type security build clean

install:
	python3 -m pip install -e ".[dev]"

test:
	pytest

coverage:
	pytest --cov=origin_audit --cov-report=term-missing

lint:
	ruff check .
	ruff format --check .

type:
	mypy src

security:
	bandit -c pyproject.toml -r src

build:
	python -m build

clean:
	python -c "import shutil; [shutil.rmtree(p, ignore_errors=True) for p in ('build','dist','.pytest_cache','.mypy_cache','.ruff_cache','htmlcov')]"
