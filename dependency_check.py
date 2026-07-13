"""
dependency_check.py
-------------------
Friendly dependency checker for the console application.
"""

import importlib.util
import sys


REQUIRED_MODULES = {
    "Crypto": "pycryptodome",
    "pandas": "pandas",
    "matplotlib": "matplotlib",
}


def ensure_required_dependencies():
    """Exit with clear install instructions if required packages are missing."""
    missing_packages = [
        package
        for module, package in REQUIRED_MODULES.items()
        if importlib.util.find_spec(module) is None
    ]

    if not missing_packages:
        return

    print("\n[!] Required Python libraries are missing:")
    for package in missing_packages:
        print(f"    - {package}")

    print("\nInstall them with:")
    print("    python -m pip install -r requirements.txt")
    print("\nThen run again:")
    print("    python main.py\n")
    sys.exit(1)
