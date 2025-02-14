import json
import os
import sys  # ✅ Add this to fix the issue
import argparse
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

CONFIG_FILE_PATH = os.path.expanduser("~/.dobconfig.json")

def load_config():
    """Load the persona config file."""
    if not os.path.exists(CONFIG_FILE_PATH):
        print(f"❌ Error: Config file not found at {CONFIG_FILE_PATH}. Please run 'dob config' first.")
        sys.exit(1)

    try:
        with open(CONFIG_FILE_PATH, "r") as config_file:
            return json.load(config_file)
    except json.JSONDecodeError:
        print(f"❌ Error: Corrupt config file at {CONFIG_FILE_PATH}. Please re-run 'dob config'.")
        sys.exit(1)

def sign_token(private_key_path, token):
    """Sign the token using the private key."""
    try:
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None)

        signature = private_key.sign(
            token.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        return signature.hex()
    except FileNotFoundError:
        print(f"❌ Error: Private key file not found at {private_key_path}.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error loading private key: {e}")
        sys.exit(1)

def forward_to_host(command_args):
    """Forward the command to the host for execution."""
    config = load_config()
    persona_name = config["persona_name"]
    token = config["token"]
    private_key_path = os.path.abspath(os.path.expanduser(config["private_key_path"]))
    host_endpoint = config["host_endpoint"]

    args = list(command_args)
    file_content = None
    if '--file-path' in args:
        file_index = args.index('--file-path') + 1
        if file_index < len(args):
            file_path = args[file_index]
            file_path = os.path.abspath(os.path.expanduser(file_path))  # Ensure full path
            if os.path.exists(file_path):
                with open(file_path, 'r') as file:
                    file_content = file.read()
                args[file_index] = "<inline_file>"
            else:
                print(f"❌ Error: File '{file_path}' not found.")
                sys.exit(1)
        else:
            print("❌ Error: '--file-path' option requires a file path.")
            sys.exit(1)

    signature = sign_token(private_key_path, token)

    headers = {
        "Persona-Name": persona_name,
        "Authorization": token,
        "Signature": signature
    }

    command_string = "dob " + " ".join(args)  # Ensure full command is sent
    print(f"📡 Forwarding command to host: {command_string}")

    try:
        response = requests.post(
            f"{host_endpoint}/execute",
            json={"command": command_string, "file_content": file_content},
            headers=headers
        )

        if response.status_code == 200:
            print(response.text)
        else:
            print(f"❌ Execution failed with status {response.status_code}: {response.text}")
            sys.exit(1)

    except requests.ConnectionError:
        print("❌ Error: Failed to connect to the host. Check your network and host endpoint.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

def config_command():
    """Handle the 'config' command with proper argument parsing."""
    if "--persona-name" not in sys.argv or "--token" not in sys.argv or "--private-key-path" not in sys.argv or "--host-endpoint" not in sys.argv:
        print("❌ Error: Missing required arguments for config.")
        print("Usage: dob config --persona-name <name> --token <token> --private-key-path <path> --host-endpoint <url>")
        sys.exit(1)

    # Extract arguments safely
    args = sys.argv[2:]
    try:
        persona_name = args[args.index("--persona-name") + 1]
        token = args[args.index("--token") + 1]
        private_key_path = args[args.index("--private-key-path") + 1]
        host_endpoint = args[args.index("--host-endpoint") + 1]
    except (ValueError, IndexError):
        print("❌ Error: Incorrect usage of config command.")
        print("Usage: dob config --persona-name <name> --token <token> --private-key-path <path> --host-endpoint <url>")
        sys.exit(1)

    private_key_path = os.path.abspath(os.path.expanduser(private_key_path))  # Expand `~` and get full path

    if not os.path.exists(private_key_path):
        print(f"❌ Error: Private key file not found at {private_key_path}.")
        sys.exit(1)

    config_data = {
        "persona_name": persona_name,
        "token": token,
        "private_key_path": private_key_path,
        "host_endpoint": host_endpoint
    }

    with open(CONFIG_FILE_PATH, "w") as config_file:
        json.dump(config_data, config_file, indent=4)
    print(f"✅ Configuration saved to {CONFIG_FILE_PATH}.")

def main():
    if len(sys.argv) < 2:
        print("Usage: dob [config|<command>]")
        sys.exit(1)

    if sys.argv[1] == "config":
        config_command()
    elif sys.argv[1] == "--help" or sys.argv[1] == "-h":
        print("Usage: dob [config|<command>]")
        print("  config: Configure the remote execution by generating a .dobconfig.json file.")
        print("  <command>: Forward any other command to the host for execution.")
    else:
        forward_to_host(sys.argv[1:])

if __name__ == "__main__":
    main()
