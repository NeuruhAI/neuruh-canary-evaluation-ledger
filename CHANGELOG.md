# Changelog

## 0.1.1a0 — v0.1.1-alpha

- `LICENSE` now carries the complete Apache-2.0 license text rather than the short boilerplate
  notice, and a `NOTICE` file carries the copyright line.
- Modern packaging metadata: PEP 639 `license`/`license-files`, `readme`, authors, project URLs.
  The previous `license = {text = "Apache-2.0"}` form is deprecated in current setuptools.
- Explicit `__all__`, so `import *` no longer re-exports standard-library names, and
  `__version__` is read from installed distribution metadata instead of a hard-coded literal.
- The CLI reports bad input instead of raising: a missing file, unreadable JSON, or a rejected
  object prints `error: ...` on stderr and exits `2`. It previously printed a Python traceback.
- README documents install, a runnable example with its expected output, the public API, the
  published schema, and the safety boundary.
- Continuous integration on Python 3.11, 3.12, and 3.13.
- No change to validation rules, digests, or schema versions.

## 0.1.0a0 — v0.1.0-alpha

- Initial public extraction.
