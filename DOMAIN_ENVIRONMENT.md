# Reproducible data-engineering environment

Upstream: https://github.com/kbandla/dpkt
Upstream commit: 4f8958eb4b375b38d0ab6ffadf2da9b24395394d
Validated on Ubuntu 26.04, 3.13.15 (main, Sep  1 2026, 14:18:08) [Clang 22.1.3 ].

Use an isolated virtual environment from this checkout:
```
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-domain.lock
python -m pip install -e .
```
Run the relevant offline baseline:
```
export PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 FAST=1
python -m pytest -q -o addopts= dpkt/pcap.py dpkt/pcapng.py dpkt/ip.py dpkt/ip6.py dpkt/tcp.py dpkt/http.py dpkt/netflow.py dpkt/ethernet.py
```
Measured test process: 0.859 seconds. Only the listed
core tests are claimed. Optional integrations and external services are not
required. Test fixtures are covered by the upstream license. New small test
inputs can be generated locally. Reset by checking out this immutable commit
in a clean directory and recreating the virtual environment.
