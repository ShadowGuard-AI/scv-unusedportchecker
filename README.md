# scv-UnusedPortChecker
The port check runs by default: it reads local netstat output with its process information and reports open listening ports whose owning process cannot be identified (no pid or program in the netstat output), with the count printed before the list. Closed ports are never reported as unused. A failed port check (netstat missing or failing) exits 1 with a port check failed line. Use --skip-ports to opt out of the port check. The configuration and schema arguments are optional: when a config is supplied, it is validated against the supplied schema. Config files may be YAML (.yaml or .yml) or JSON.

## Install
`git clone https://github.com/ShadowGuardAI/scv-unusedportchecker`

## Usage
`./scv-unusedportchecker [params]`

## Parameters
- `-h`: Show help message and exit
- `-c`: Path to the configuration file (YAML or JSON). Optional.
- `-s`: Path to the JSON schema file. Required when a configuration file is supplied.
- `-l`: Path to the log file. If not specified, logs will be printed to the console.
- `--check-ports`: Run the port check (this is the default; kept for compatibility).
- `--skip-ports`: Skip the port check.

## License
Copyright (c) ShadowGuardAI
