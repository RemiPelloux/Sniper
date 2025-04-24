#!/usr/bin/env python
"""
Fix ZAP API dependency issues by ensuring the correct import path is used.
This script creates a custom import handler in the OWASP ZAP integration.
"""

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

# Get the Sniper project root directory
project_root = Path(__file__).parent.parent.absolute()
zap_integration_file = project_root / "src" / "integrations" / "owasp_zap.py"


# Check if zaproxy is installed in the current Python environment
def check_zaproxy_installed():
    try:
        import zaproxy

        print(f"✅ zaproxy is installed at {zaproxy.__file__}")
        return True
    except ImportError:
        print("❌ zaproxy is not installed in the current Python environment")
        return False


# Install zaproxy using the current Python environment
def install_zaproxy():
    print("📦 Installing zaproxy...")
    try:
        # First check if we're in a Poetry environment
        if os.environ.get("VIRTUAL_ENV") and "poetry" in os.environ.get(
            "VIRTUAL_ENV", ""
        ):
            # We're in a Poetry virtual environment
            subprocess.check_call([sys.executable, "-m", "pip", "install", "zaproxy"])
        else:
            # If not, try using Poetry directly
            subprocess.check_call(["poetry", "add", "zaproxy"])
        print("✅ zaproxy successfully installed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install zaproxy: {e}")
        return False


# Fix the import in the OWASP ZAP integration file
def fix_zap_integration_file():
    if not zap_integration_file.exists():
        print(f"❌ ZAP integration file not found at {zap_integration_file}")
        return False

    # Read the current content
    with open(zap_integration_file, "r") as f:
        content = f.read()

    # Check if we need to modify the file
    if "import zaproxy" not in content:
        print("⚠️ Adding zaproxy import to integration file")

        # Find the import section
        import_section_end = content.find("\n\n", content.find("import"))
        if import_section_end == -1:
            # Fallback to just after the first imports
            import_section_end = content.find("\n", content.find("import"))

        # Add our import
        modified_content = (
            content[:import_section_end]
            + '\n\n# Import zaproxy with error handling\ntry:\n    import zaproxy\n    ZAP_API_AVAILABLE = True\nexcept ImportError:\n    ZAP_API_AVAILABLE = False\n    logging.warning("ZAP Python API not installed. Install with: pip install zaproxy")\n'
            + content[import_section_end:]
        )

        # Find the existing conditional check and replace it
        api_check_start = modified_content.find("try:\n    from zapv2")
        if api_check_start != -1:
            api_check_end = modified_content.find(
                "except ImportError:", api_check_start
            )
            end_of_block = modified_content.find("\n\n", api_check_end)
            if end_of_block == -1:
                end_of_block = len(modified_content)

            # Replace with our conditional based on our import check
            modified_content = (
                modified_content[:api_check_start]
                + "if ZAP_API_AVAILABLE:\n    from zapv2 import ZAPv2\nelse:\n    ZAPv2 = None\n"
                + modified_content[end_of_block:]
            )

        # Write the modified content
        with open(zap_integration_file, "w") as f:
            f.write(modified_content)

        print(f"✅ Modified ZAP integration file at {zap_integration_file}")
        return True
    else:
        print("✅ ZAP integration file already has the zaproxy import")
        return True


def main():
    print("🔍 Checking for zaproxy installation...")
    zaproxy_installed = check_zaproxy_installed()

    if not zaproxy_installed:
        success = install_zaproxy()
        if not success:
            print("❌ Failed to install zaproxy, please install it manually with:")
            print("   poetry add zaproxy")
            return

    # Fix the integration file either way
    fix_zap_integration_file()

    print("\n✨ ZAP dependency issue should now be fixed.\n")
    print("You can test it by running:")
    print(f"   poetry run python {project_root}/scripts/check_plugins.py")
    print("or:")
    print("   poetry run sniper --version")


if __name__ == "__main__":
    main()
