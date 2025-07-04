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
CONFIG_FILE_FORMATS = ["yaml", "json"]


def setup_argparse() -> argparse.ArgumentParser:
    """Sets up the argument parser for the tool.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="scv-UnusedPortChecker: Validates security configurations against defined security policies."
    )
    parser.add_argument(
        "-c",
        "--config",
        dest="config_file",
        required=True,
        help="Path to the configuration file (YAML or JSON).",
    )
    parser.add_argument(
        "-s",
        "--schema",
        dest="schema_file",
        required=True,
        help="Path to the JSON schema file.",
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
        help="Enable unused port check after configuration validation.",
    )
    parser.add_argument(
        "--offensive",
        action="store_true",
        help="Enable offensive security tests (e.g., check for common vulnerabilities).",
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
            if file_extension == "yaml":
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


def find_unused_ports() -> List[int]:
    """Identifies open ports on the system that are not associated with any running process.

    Returns:
        List[int]: A list of unused port numbers.
    """
    try:
        # Get a list of all used ports
        used_ports = set()
        netstat_output = subprocess.check_output(["netstat", "-an"], text=True).splitlines()

        for line in netstat_output:
            parts = line.split()
            if len(parts) > 4 and (
                "LISTEN" in parts or "ESTABLISHED" in parts or "CLOSE_WAIT" in parts
            ):
                address = parts[3]
                if ":" in address:
                    try:
                        port = int(address.split(":")[-1])
                        used_ports.add(port)
                    except ValueError:
                        pass  # Ignore non-integer port values

        # Check ports from 1 to 65535 for availability
        unused_ports = []
        for port in range(1, 65536):
            if port not in used_ports:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.1)  # Short timeout
                        result = s.connect_ex(("127.0.0.1", port))
                        if result != 0:  # Port is likely unused
                            unused_ports.append(port)
                except Exception:
                    pass  # Ignore errors during connection attempt

        return unused_ports

    except subprocess.CalledProcessError as e:
        logging.error(f"Error running netstat: {e}")
        return []
    except Exception as e:
        logging.error(f"An unexpected error occurred while checking for unused ports: {e}")
        return []


def perform_offensive_tests(config: Dict[str, Any]) -> None:
    """Performs basic offensive security tests.

    Args:
        config (Dict[str, Any]): The validated configuration data.

    Raises:
        NotImplementedError: If offensive testing is enabled but not implemented.
    """
    # Check for default credentials, insecure configurations, etc.
    # This is a placeholder for actual offensive security checks.
    # For example, check if 'admin' is a username, or if passwords are in plain text

    logging.warning(
        "Offensive security tests are enabled but currently contain placeholder implementation."
    )

    # Placeholder example: Check for 'admin' username (highly simplified example)
    if "users" in config and isinstance(config["users"], list):
        for user in config["users"]:
            if isinstance(user, dict) and "username" in user:
                if user["username"] == "admin":
                    logging.warning(
                        "Potential vulnerability: Default username 'admin' found in configuration."
                    )

    # Placeholder example: Check for plain text passwords
    if "passwords" in config and isinstance(config["passwords"], list):
        logging.warning(
            "Potential vulnerability: Passwords found in plain text in the configuration."
        )

    # Implement more thorough offensive tests based on the specific configuration and application.


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
        # Load and validate the configuration
        config = load_config(args.config_file)
        schema = load_schema(args.schema_file)
        validate_config(config, schema)
        logging.info("Configuration validation successful.")

        # Check for unused ports if requested
        if args.check_ports:
            unused_ports = find_unused_ports()
            if unused_ports:
                logging.warning(f"Unused ports found: {unused_ports}")
            else:
                logging.info("No unused ports found.")

        # Perform offensive security tests if requested
        if args.offensive:
            perform_offensive_tests(config)

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
# Create a sample config.yaml, schema.json
# Run the script:
# python main.py -c config.yaml -s schema.json --check-ports --offensive
# or, to log to a file:
# python main.py -c config.yaml -s schema.json --log scv.log --check-ports