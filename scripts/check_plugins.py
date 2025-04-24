#!/usr/bin/env python
"""
Script to check all plugins and integrations for the Sniper Security Tool.
This script attempts to import each plugin and integration to verify that
all required dependencies are installed.
"""

import importlib
import os
import sys
from typing import Dict, List, Tuple

import pkg_resources

# Add the src directory to the path so we can import Sniper modules
src_path = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"
)
sys.path.insert(0, src_path)


class StatusChecker:
    """Check the status of all Sniper plugins and integrations."""

    def __init__(self):
        self.results: Dict[str, List[Tuple[str, bool, str]]] = {
            "Integrations": [],
            "Plugins": [],
            "ML Modules": [],
            "Core Components": [],
        }

        self.required_packages = {
            "zaproxy": "OWASP ZAP Integration",
            "nmap": "Nmap Integration",
            "wappalyzer": "Wappalyzer Integration",
            "dirsearch": "Dirsearch Integration",
            "sublist3r": "Sublist3r Integration",
            "pandas": "ML Modules",
            "scikit-learn": "ML Modules",
            "numpy": "ML Modules",
            "matplotlib": "ML Visualization",
            "typer": "CLI Framework",
            "rich": "User Interface",
            "pydantic": "Data Validation",
            "fastapi": "REST API",
            "docker": "Sandbox Plugin",
            "aiohttp": "Distributed Architecture",
        }

    def check_package_installed(self, package_name: str) -> bool:
        """Check if a package is installed."""
        try:
            pkg_resources.get_distribution(package_name)
            return True
        except pkg_resources.DistributionNotFound:
            return False

    def check_module_importable(self, module_name: str) -> Tuple[bool, str]:
        """Check if a module can be imported."""
        try:
            importlib.import_module(module_name)
            return True, "OK"
        except ImportError as e:
            return False, str(e)
        except Exception as e:
            return False, f"Unexpected error: {str(e)}"

    def check_integrations(self):
        """Check all tool integrations."""
        integration_modules = [
            ("src.integrations.nmap", "Nmap"),
            ("src.integrations.owasp_zap", "OWASP ZAP"),
            ("src.integrations.dirsearch", "Dirsearch"),
            ("src.integrations.sublist3r", "Sublist3r"),
            ("src.integrations.wappalyzer", "Wappalyzer"),
            ("src.integrations.vulnerability_scanner", "Custom Vulnerability Scanner"),
        ]

        for module, name in integration_modules:
            importable, error = self.check_module_importable(module)
            self.results["Integrations"].append(
                (name, importable, error if not importable else "OK")
            )

    def check_plugins(self):
        """Check all plugins."""
        # Check sandbox plugin
        importable, error = self.check_module_importable(
            "src.sniper.plugins.sandbox.sandbox_plugin"
        )
        self.results["Plugins"].append(
            ("Sandbox Plugin", importable, error if not importable else "OK")
        )

        # Try to discover other plugins
        try:
            from src.core.plugin_manager import PluginManager

            plugin_manager = PluginManager()
            discovered = plugin_manager.discover_plugins()
            for plugin_class in discovered:
                name = getattr(plugin_class, "name", plugin_class.__name__)
                self.results["Plugins"].append((name, True, "Discovered"))
        except Exception as e:
            self.results["Plugins"].append(("Plugin Discovery", False, str(e)))

    def check_ml_modules(self):
        """Check machine learning modules."""
        ml_modules = [
            ("src.ml.prediction", "ML Prediction"),
            ("src.ml.risk_scoring", "Risk Scoring"),
            ("src.ml.smart_recon", "Smart Reconnaissance"),
            ("src.ml.tool_selection", "Tool Selection"),
            ("src.ml.pattern_learning", "Pattern Learning"),
        ]

        for module, name in ml_modules:
            importable, error = self.check_module_importable(module)
            self.results["ML Modules"].append(
                (name, importable, error if not importable else "OK")
            )

    def check_core_components(self):
        """Check core Sniper components."""
        core_modules = [
            ("src.cli.main", "CLI Main"),
            ("src.core.config", "Configuration"),
            ("src.distributed.master", "Distributed Master"),
            ("src.distributed.worker", "Distributed Worker"),
            ("src.distributed.client", "Distributed Client"),
            ("src.results.normalizers.base_normalizer", "Result Normalizers"),
            ("src.reporting.report_generator", "Reporting"),
        ]

        for module, name in core_modules:
            importable, error = self.check_module_importable(module)
            self.results["Core Components"].append(
                (name, importable, error if not importable else "OK")
            )

    def check_required_packages(self):
        """Check if all required packages are installed."""
        print("\n=== Required Packages ===")
        print(f"{'Package':<20} {'Status':<10} {'Used By':<25}")
        print("-" * 55)

        for package, used_by in self.required_packages.items():
            installed = self.check_package_installed(package)
            status = "INSTALLED" if installed else "MISSING"
            print(f"{package:<20} {status:<10} {used_by:<25}")

    def run_all_checks(self):
        """Run all checks and print results."""
        self.check_integrations()
        self.check_plugins()
        self.check_ml_modules()
        self.check_core_components()

        print("\n=== Sniper Components Status ===\n")

        for category, checks in self.results.items():
            print(f"\n=== {category} ===")
            print(f"{'Component':<30} {'Status':<10} {'Details':<40}")
            print("-" * 80)

            for name, status, message in checks:
                status_str = "OK" if status else "FAILED"
                print(f"{name:<30} {status_str:<10} {message:<40}")

        self.check_required_packages()

        # Print summary
        all_checks = [item for sublist in self.results.values() for item in sublist]
        total = len(all_checks)
        passed = sum(1 for _, status, _ in all_checks if status)

        print(f"\n=== Summary ===")
        print(f"Total components checked: {total}")
        print(f"Components OK: {passed}")
        print(f"Components with issues: {total - passed}")

        if total - passed > 0:
            print("\nSuggestions to fix issues:")
            print("1. Run: poetry install --no-dev")
            print("2. For specific packages: poetry add <package-name>")
            print("3. Check log messages for specific error details")
            print("4. Verify that the source code structure is correct")


if __name__ == "__main__":
    checker = StatusChecker()
    checker.run_all_checks()
