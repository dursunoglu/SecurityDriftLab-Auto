# Update Instructions

Copy these files into your project:

```bash
cp db.py src/securitydriftlab/db.py
cp sdi.py src/securitydriftlab/sdi.py
cp exports.py src/securitydriftlab/exports.py
cp run_statistical_tests.py scripts/run_statistical_tests.py
```

Then run:

```bash
python scripts/recompute_sdi_after_semgrep.py
python scripts/run_statistical_tests.py
```

This adds:
- SDI
- SW-SDI
- SRR
- VC
