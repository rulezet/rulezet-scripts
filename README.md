# rulezet-scripts

A collection of scripts to support the use of rulezet.org.

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

## rulezet-suricata.py

Fetch Suricata rules from [Rulezet](https://rulezet.org/) and save them as local files or as a consolidated rules file for Suricata to load.

### Features

- Search public Suricata rules from Rulezet
- Print fetched rules
- Save each rule as an individual `.rules` file
- Build one aggregate `.rules` file for Suricata
- Optionally run a Suricata config test command and reload command

### Requirements

- Python 3
- `requests`
- Suricata tools (`suricata`, `suricatasc`) only if using `--test-command` / `--reload-command`

### Usage

#### Print matching Suricata rules:

```bash
python3 rulezet-suricata.py --search ransomware --print-rules
```

#### Save rules in a directory:

```bash
python3 rulezet-suricata.py --search ransomware --save-dir ./suricata-rules
```

#### Write one rule file to be loaded by Suricata:

```bash
python3 rulezet-suricata.py --search ransomware --output-file /etc/suricata/rules/rulezet.rules
```

#### Write rules, validate config, and reload Suricata:

```bash
python3 rulezet-suricata.py \
  --search ransomware \
  --output-file /etc/suricata/rules/rulezet.rules \
  --test-command "suricata -T -c /etc/suricata/suricata.yaml -S /etc/suricata/rules/rulezet.rules" \
  --reload-command "suricatasc -c reload-rules"
```
