# YAML parser instructions

## Prerequisites

### [Install Rust](https://www.rust-lang.org/tools/install)

## Build and run the parser

### Program arguments

```bash
Usage: yaml_rust [OPTIONS] --cfg-path <CFG_PATH>

Options:
      --cfg-type <CFG_TYPE>  Format of the policy files [default: yaml], supported file types: yaml
      --cfg-path <CFG_PATH>  Path to the policy file or directory that contains the policy files
  -h, --help                 Print help
```

### Supported features

#### "debug": prints debug information on screen

```bash
cargo run -F debug --  --cfg-type <CFG_TYPE> --cfg-path <CFG_PATH>
```

### Run in development mode

```bash
cargo run -- --cfg-type <CFG_TYPE> --cfg-path <CFG_PATH>
```

### Run in release mode

```bash
cargo run --release -- --cfg-type <CFG_TYPE> --cfg-path <CFG_PATH>
```

### Examples

```bash
cargo run -F debug --  --cfg-type yaml --cfg-path ../../policies/http.yaml
```

```bash
cargo run --release --  --cfg-type yaml --cfg-path ../../policies/
```