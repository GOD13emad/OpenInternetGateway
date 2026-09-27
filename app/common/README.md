# Generated runtime data

This directory is intentionally kept in source control, but its runtime contents are not.

Release engineering or the platform Config Factory populates:

- `runtime/udp-cache/`
- `runtime/config-factory/`
- `evidence/vpngate-mirror-api.csv`

Generated relay profiles and provider material are excluded from Git. A fresh source build can regenerate its local pool from supported public sources before packaging.
