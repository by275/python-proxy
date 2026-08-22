# Migration Notes

## Build and installation interface

The redundant `setup.py` compatibility shim was removed after the project was
validated with the PEP 517 configuration in `pyproject.toml`. This is the only
breaking change in the follow-up modernization work.

Use the supported Git installation form:

```text
python -m pip install "git+https://github.com/<owner>/<repository>.git"
```

For a local checkout, use:

```text
python -m pip install .
python -m pip install -e .
python -m build --wheel
```

Replace old commands as follows:

| Old command | Replacement |
| --- | --- |
| `python setup.py install` | `python -m pip install .` |
| `python setup.py develop` | `python -m pip install -e .` |
| `python setup.py bdist_wheel` | `python -m build --wheel` |
| `python setup.py sdist` | `python -m build --sdist` |

The package name, Python requirement, console entry point, optional extras, package
data, and runtime protocol behavior are unchanged. Existing `pproxy` CLI options,
URI syntax, public compatibility facades, wire formats, and cipher fallback policy
remain supported.

To roll back the build-interface change in a private checkout, revert the dedicated
`build: remove legacy setup.py shim` commit and reinstall the checkout. No runtime
state migration is required.
