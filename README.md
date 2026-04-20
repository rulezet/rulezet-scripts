# rulezet-scripts

A collection of scripts to support the use of rulezet.org

## rulezet-yara.py

Fetch YARA rules from [Rulezet](https://rulezet.org/) and optionally run them locally against a file or directory.

### Features

- Search public YARA rules from Rulezet
- Print fetched rules
- Save rules as local `.yar` files
- Run fetched rules locally with `yara-python`

### Requirements

- Python 3
- `requests`
- `yara-python`

### Usage 

#### Print matching rules:

```bash
python3 rulezet-yara.py --search CVE-2025-53521 --print-rules
```

#### Save rules locally:

```bash
python3 rulezet-yara.py --search CVE-2025-53521 --save-dir ./rules
```

#### Scan a file:

```bash
python3 rulezet-yara.py --search CVE-2025-53521 --run /path/to/file
```

#### Scan a directory recursively:

```bash
python3 rulezet-yara.py --search CVE-2025-53521 --run /path/to/dir --recursive
```

#### Show scan results as JSON:

```bash
python3 rulezet-yara.py --search CVE-2025-53521 --run /path/to/dir --recursive --json
```
