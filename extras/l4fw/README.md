### Build the VPP code-base:

```bash
./scripts/build_and_run.sh -b
```

### Run VPP with network namespaces:

```bash
./scripts/build_and_run.sh -r
```

### Load YAML policy files into VPP

```bash
./scripts/l4fw-load-rules.py ./policies/**/*.yaml
```