# scv-UnusedPortChecker
Identifies open ports on a system that are not associated with any running process, indicating potential misconfigurations or abandoned services. - Focused on Validates security configurations (e.g., application configurations, infrastructure-as-code templates) against defined security policies. Reads configuration files, parses them, and verifies adherence to specified security rules.  Supports YAML or JSON formats.  Alerts on deviations from the security baseline.

## Install
`git clone https://github.com/ShadowGuardAI/scv-unusedportchecker`

## Usage
`./scv-unusedportchecker [params]`

## Parameters
- `-h`: Show help message and exit
- `-c`: No description provided
- `-s`: Path to the JSON schema file.
- `-l`: Path to the log file. If not specified, logs will be printed to the console.
- `--check-ports`: Enable unused port check after configuration validation.
- `--offensive`: No description provided

## License
Copyright (c) ShadowGuardAI
