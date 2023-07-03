# meraki-OneAdP

Meraki Golden Adaptive Policy

This tool will clone the Adaptive Policy Groups, ACLs and Policies from a source Organtization to one or many other organizations.

[Meraki Adaptive Policy Overview](https://documentation.meraki.com/General_Administration/Cross-Platform_Content/Adaptive_Policy/Adaptive_Policy_Overview)

### Clone and setup

```bash
git clone https://github.com/ez1mm/meraki-OneAdP && cd meraki-OneAdP
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Usage
### set API key
```bash
export APIKEY=<apikey>
```
Golden Organization can be specified via config file or via command line.
Destination Orgs can be defined in config file, if none defined, Golden Config will push to all eligible Orgs
Config file takes precedence over command line options.

`config.py` Configuration file for Golden Org and Destination Orgs
```
GOLDEN_ORG = 'THE_ONE_TRUE_ORG'
ADP_ORGS = [
    'DEST_ORG_1',
    'DEST_ORG_2',
    'DEST_ORG_3'
]
```

### Options
`moap.py` Adaptive Policy clone tool
```
usage: moap.py [-h] [-o O] [--log] [-v] [-d]

Select options.

options:
  -h, --help  show this help message and exit
  -o O        Organization name for operation
  --log       Log to file
  -v          verbose
  -d          debug
```

### Caveats
* Requires Destination Organization to have at least one Adaptive Policy Network Enabled
* Currently only clones to Organizations with no Adaptive Policy Groups/ACLs/Policies

### TODO
* Look at options for Organizations with AdP settings that differ from the Golden Config - overwrite? merge?
* Pause before applying output?
