import argparse
import json
import logging
import os
import socket
import subprocess
import sys
import time
from typing import Any, Dict, List, Union

import yaml
from jsonschema import validate, ValidationError

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Constants
CONFIG_FILE_FORMATS = ["yaml", "yml", "json"]


def setup_argparse() -> argparse.ArgumentParser:
    """Sets up the argument parser for the tool.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="scv-UnusedPortChecker: Reports open listening ports whose owning process cannot be identified, and optionally validates a configuration file."
    )
    parser.add_argument(
        "-c",
        "--config",
        dest="config_file",
        required=False,
        default=None,
        help="Path to the configuration file (YAML or JSON). Optional; when supplied, it is validated against the schema.",
    )
    parser.add_argument(
        "-s",
        "--schema",
        dest="schema_file",
        required=False,
        default=None,
        help="Path to the JSON schema file. Required when a configuration file is supplied.",
    )
    parser.add_argument(
        "-l",
        "--log",
        dest="log_file",
        help="Path to the log file. If not specified, logs will be printed to the console.",
    )
    parser.add_argument(
        "--check-ports",
        action="store_true",
        help="Run the port check (this is the default; kept for compatibility).",
    )
    parser.add_argument(
        "--skip-ports",
        action="store_true",
        help="Skip the port check. Only the configuration validation, when a config is supplied, runs.",
    )

    return parser


def load_config(config_file: str) -> Dict[str, Any]:
    """Loads the configuration from a YAML or JSON file.

    Args:
        config_file (str): Path to the configuration file.

    Returns:
        Dict[str, Any]: The configuration as a dictionary.

    Raises:
        FileNotFoundError: If the configuration file does not exist.
        ValueError: If the file format is not supported.
        yaml.YAMLError: If the YAML file is invalid.
        json.JSONDecodeError: If the JSON file is invalid.
    """
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Configuration file not found: {config_file}")

    file_extension = config_file.split(".")[-1].lower()
    if file_extension not in CONFIG_FILE_FORMATS:
        raise ValueError(
            f"Unsupported configuration file format: {file_extension}. "
            f"Supported formats are: {', '.join(CONFIG_FILE_FORMATS)}"
        )

    try:
        with open(config_file, "r") as f:
            if file_extension in ("yaml", "yml"):
                config = yaml.safe_load(f)
            else:  # JSON
                config = json.load(f)
        return config
    except yaml.YAMLError as e:
        raise yaml.YAMLError(f"Error parsing YAML file: {e}")
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(f"Error parsing JSON file: {e}", e.doc, e.pos)
    except Exception as e:
        raise Exception(f"An unexpected error occurred while loading config file: {e}")


def load_schema(schema_file: str) -> Dict[str, Any]:
    """Loads the JSON schema from a file.

    Args:
        schema_file (str): Path to the JSON schema file.

    Returns:
        Dict[str, Any]: The JSON schema as a dictionary.

    Raises:
        FileNotFoundError: If the schema file does not exist.
        json.JSONDecodeError: If the JSON file is invalid.
    """
    if not os.path.exists(schema_file):
        raise FileNotFoundError(f"Schema file not found: {schema_file}")

    try:
        with open(schema_file, "r") as f:
            schema = json.load(f)
        return schema
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(f"Error parsing JSON file: {e}", e.doc, e.pos)
    except Exception as e:
        raise Exception(f"An unexpected error occurred while loading schema file: {e}")


def validate_config(config: Dict[str, Any], schema: Dict[str, Any]) -> None:
    """Validates the configuration against the JSON schema.

    Args:
        config (Dict[str, Any]): The configuration to validate.
        schema (Dict[str, Any]): The JSON schema to use for validation.

    Raises:
        jsonschema.ValidationError: If the configuration does not match the schema.
    """
    try:
        validate(instance=config, schema=schema)
    except ValidationError as e:
        raise ValidationError(f"Configuration validation failed: {e}")
    except Exception as e:
        raise Exception(f"An unexpected error occurred during validation: {e}")


def find_unused_ports():
    """Find open listening ports whose owning process cannot be identified.

    Reads local netstat output with its process information (the
    process flag the platform offers, -p on Linux), parses the pid
    and program fields where present, and reports listening ports
    with no pid or program in that output. Closed ports are never
    reported.

    Returns:
        List[int]: Sorted listening ports with no identified owner,
        or None when the port check itself failed (netstat missing
        or failing), which is distinct from a completed check that
        found nothing.
    """
    try:
        # I ask netstat for the Linux form of the process flag. On a platform where that flag means something else or does not exist, the command fails as a whole and I return None, so the port check reports itself broken rather than guessing from weaker output.
        netstat_output = subprocess.check_output(
            ["netstat", "-anp"], text=True, stderr=subprocess.STDOUT
        ).splitlines()
    except Exception as e:
        logging.error(f"Error running netstat: {e}")
        return None

    unidentified = []
    for line in netstat_output:
        parts = line.split()
        # Requiring the LISTEN token means UDP listeners are invisible to me by construction: UDP rows carry no state word, so an unattended UDP service never appears in my report no matter how long it has been bound.
        if len(parts) < 6 or "LISTEN" not in parts:
            continue
        address = parts[3]
        if ":" not in address:
            continue
        try:
            port = int(address.split(":")[-1])
        except ValueError:
            continue
        pid = None
        program = None
        if len(parts) > 6:
            # Column seven is the process field only in the layout I expect. A build of netstat that adds or drops a column shifts every field, and my parser then reads a foreign queue value or an address fragment as the process text and judges the port unidentified.
            proc_field = parts[6]
            if proc_field and proc_field != "-":
                if "/" in proc_field:
                    pid_text, program = proc_field.split("/", 1)
                    pid = pid_text or None
                    program = program or None
                elif proc_field.isdigit():
                    pid = proc_field
        # Running without enough privilege makes netstat print a dash for processes owned by other users. I cannot separate that dash from a genuinely ownerless listener, so an unprivileged run reports other people's services as unidentified, which is the loudest false alarm this tool produces.
        if not pid or not program:
            unidentified.append(port)
    # The set fold merges the same port number across protocols and address families. A port that is identified over IPv4 and unidentified over IPv6 is reported once, with no hint of which family raised the flag.
    return sorted(set(unidentified))


def main() -> int:
    """Main function of the script."""
    parser = setup_argparse()
    args = parser.parse_args()

    # Configure logging to file if specified
    if args.log_file:
        file_handler = logging.FileHandler(args.log_file)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        )
        logging.getLogger().addHandler(file_handler)

    try:
        # Config validation runs only when a config is supplied.
        if args.config_file or args.schema_file:
            if not args.config_file or not args.schema_file:
                logging.error("Both a configuration file and a schema file are required for validation.")
                return 1
            config = load_config(args.config_file)
            schema = load_schema(args.schema_file)
            validate_config(config, schema)
            logging.info("Configuration validation successful.")

        # The port check runs by default; --skip-ports opts out.
        if not args.skip_ports:
            unused_ports = find_unused_ports()
            if unused_ports is None:
                logging.error("Port check failed.")
                print("Port check failed.")
                return 1
            print(f"Open listening ports with no identified owning process: {len(unused_ports)}")
            if unused_ports:
                logging.warning(f"Unused ports found: {unused_ports}")
            else:
                logging.info("No unused ports found.")

        return 0  # Success

    except FileNotFoundError as e:
        logging.error(e)
        return 1  # Error
    except ValueError as e:
        logging.error(e)
        return 1  # Error
    except yaml.YAMLError as e:
        logging.error(e)
        return 1  # Error
    except json.JSONDecodeError as e:
        logging.error(e)
        return 1  # Error
    except ValidationError as e:
        logging.error(e)
        return 1  # Error
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return 1  # Error


if __name__ == "__main__":
    sys.exit(main())


# Example usage:
# Run the port check on its own:
# python main.py
# Or with configuration validation as well:
# python main.py -c config.yaml -s schema.json
# Or validation only:
# python main.py -c config.yaml -s schema.json --skip-ports