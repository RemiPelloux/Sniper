#!/usr/bin/env python
"""
Script to generate a comprehensive status report of all Sniper components.
This includes plugins, integrations, dependencies, and system requirements.
"""

import importlib
import os
import sys
import subprocess
import json
import shutil
from typing import Dict, List, Any, Tuple, Optional, Union
import pkg_resources
from pathlib import Path
from rich.console import Console
from rich.table import Table

# Add the src directory to the path
src_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, src_path)

class SniperStatusReport:
    """Generate a comprehensive status report for the Sniper security tool."""
    
    def __init__(self):
        self.console = Console()
        self.project_root = Path(__file__).parent.parent.absolute()
        
        # Structure to hold component info
        self.components = {
            "core": [],
            "plugins": [],
            "integrations": [],
            "ml_modules": [],
            "dependencies": {}
        }
        
        # Tools and their discovery method
        self.tools = {
            "nmap": {"package": "python-nmap", "executable": "nmap", "docker_image": "instrumentisto/nmap"},
            "zap": {"package": "zaproxy", "executable": ["zap.sh", "zap"], "docker_image": "owasp/zap2docker-stable"},
            "dirsearch": {"package": None, "executable": "dirsearch", "docker_image": "knqyf263/dirsearch"},
            "sublist3r": {"package": None, "executable": "sublist3r", "docker_image": "secsi/sublist3r"},
            "wappalyzer": {"package": "python-Wappalyzer", "executable": "wappalyzer", "docker_image": "wappalyzer/cli"}
        }
        
        # Poetry metadata
        self.poetry_metadata = self._get_poetry_metadata()

    def _get_poetry_metadata(self) -> Dict[str, Any]:
        """Get metadata from Poetry project."""
        try:
            result = subprocess.run(
                ["poetry", "show", "--no-ansi", "--format", "json"],
                capture_output=True,
                text=True,
                check=True
            )
            return json.loads(result.stdout)
        except (subprocess.SubprocessError, json.JSONDecodeError):
            return {}

    def check_package_installed(self, package_name: str) -> Dict[str, Any]:
        """Check if a Python package is installed and get its version."""
        try:
            pkg = pkg_resources.get_distribution(package_name)
            return {
                "installed": True,
                "version": pkg.version,
                "location": pkg.location
            }
        except pkg_resources.DistributionNotFound:
            return {"installed": False}
    
    def check_executable_available(self, executable_name: Union[str, List[str]]) -> Dict[str, Any]:
        """Check if an executable is available in the system path."""
        if isinstance(executable_name, list):
            for name in executable_name:
                path = shutil.which(name)
                if path:
                    return {
                        "available": True,
                        "path": path
                    }
            return {"available": False}
        else:
            path = shutil.which(executable_name)
            return {
                "available": True,
                "path": path
            } if path else {"available": False}
    
    def check_docker_image_available(self, image_name: str) -> Dict[str, Any]:
        """Check if a Docker image is available locally."""
        try:
            result = subprocess.run(
                ["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}", image_name],
                capture_output=True,
                text=True,
                check=True
            )
            available = bool(result.stdout.strip())
            return {
                "available": available,
                "details": result.stdout.strip() if available else "Not found locally"
            }
        except subprocess.SubprocessError:
            return {
                "available": False,
                "details": "Error checking for image"
            }
    
    def check_tool_status(self, tool_name: str) -> Dict[str, Any]:
        """Check the status of a security tool."""
        tool_info = self.tools.get(tool_name, {})
        status = {
            "name": tool_name,
            "package": {"installed": False},
            "executable": {"available": False},
            "docker": {"available": False}
        }
        
        # Check package if applicable
        if tool_info.get("package"):
            status["package"] = self.check_package_installed(tool_info["package"])
        
        # Check executable
        if tool_info.get("executable"):
            status["executable"] = self.check_executable_available(tool_info["executable"])
        
        # Check Docker image
        if tool_info.get("docker_image"):
            status["docker"] = self.check_docker_image_available(tool_info["docker_image"])
        
        return status
    
    def check_all_tools(self) -> None:
        """Check all security tools."""
        for tool_name in self.tools:
            self.components["integrations"].append({
                "name": tool_name,
                "status": self.check_tool_status(tool_name)
            })
    
    def check_core_modules(self) -> None:
        """Check core Sniper modules."""
        core_modules = [
            "cli.main",
            "core.config",
            "distributed.master",
            "distributed.worker",
            "results.normalizers.base_normalizer",
            "reporting.report_generator"
        ]
        
        for module in core_modules:
            try:
                importlib.import_module(f"src.{module}")
                self.components["core"].append({
                    "name": module,
                    "status": "OK"
                })
            except ImportError as e:
                self.components["core"].append({
                    "name": module,
                    "status": "FAILED",
                    "error": str(e)
                })
    
    def check_plugins(self) -> None:
        """Check Sniper plugins."""
        try:
            from src.core.plugin_manager import PluginManager
            plugin_manager = PluginManager()
            discovered = plugin_manager.discover_plugins()
            for plugin_class in discovered:
                name = getattr(plugin_class, "name", plugin_class.__name__)
                self.components["plugins"].append({
                    "name": name,
                    "status": "DISCOVERED"
                })
        except ImportError as e:
            self.components["plugins"].append({
                "name": "Plugin System",
                "status": "FAILED",
                "error": str(e)
            })
    
    def check_ml_modules(self) -> None:
        """Check machine learning modules."""
        ml_modules = [
            "ml.prediction",
            "ml.risk_scoring",
            "ml.smart_recon",
            "ml.tool_selection",
            "ml.pattern_learning"
        ]
        
        for module in ml_modules:
            try:
                importlib.import_module(f"src.{module}")
                self.components["ml_modules"].append({
                    "name": module,
                    "status": "OK"
                })
            except ImportError as e:
                self.components["ml_modules"].append({
                    "name": module,
                    "status": "FAILED",
                    "error": str(e)
                })
    
    def check_dependencies(self) -> None:
        """Check dependencies from poetry.lock."""
        essential_deps = {
            "typer": "CLI Framework",
            "rich": "User Interface",
            "pydantic": "Data Validation",
            "fastapi": "REST API",
            "scikit-learn": "Machine Learning",
            "pandas": "Data Processing",
            "zaproxy": "OWASP ZAP Integration",
            "aiohttp": "Async HTTP Client",
            "docker": "Docker Integration",
            "python-nmap": "Nmap Integration"
        }
        
        # Check both from Poetry metadata and pkg_resources
        for dep, description in essential_deps.items():
            poetry_info = next((p for p in self.poetry_metadata if p.get("name") == dep), None)
            pkg_info = self.check_package_installed(dep)
            
            self.components["dependencies"][dep] = {
                "description": description,
                "installed": pkg_info.get("installed", False),
                "version": pkg_info.get("version") if pkg_info.get("installed") else None,
                "in_poetry": poetry_info is not None,
                "poetry_version": poetry_info.get("version") if poetry_info else None
            }
    
    def generate_report(self) -> None:
        """Generate the comprehensive status report."""
        self.check_core_modules()
        self.check_plugins()
        import shutil  # Import here to avoid module scope issues
        self.check_all_tools()
        self.check_ml_modules()
        self.check_dependencies()
        
        # Print the report
        self.console.print("\n[bold blue]===== Sniper Security Tool Status Report =====\n")
        
        # Core Modules
        self._print_module_table("Core Modules", self.components["core"])
        
        # Plugins
        self._print_module_table("Plugins", self.components["plugins"])
        
        # Integrations (Tools)
        self.console.print("\n[bold cyan]Integrations (Security Tools)[/bold cyan]")
        for tool in self.components["integrations"]:
            status = tool["status"]
            name = tool["name"].upper()
            
            # Determine overall availability
            pkg_avail = status.get("package", {}).get("installed", False)
            exe_avail = status.get("executable", {}).get("available", False) 
            docker_avail = status.get("docker", {}).get("available", False)
            available = pkg_avail or exe_avail or docker_avail
            
            self.console.print(f"\n[bold]{'✅' if available else '❌'} {name}[/bold]")
            
            if status.get("package"):
                pkg_status = status["package"]
                if pkg_status.get("installed"):
                    self.console.print(f"  Package: [green]Installed[/green] (v{pkg_status.get('version')})")
                else:
                    self.console.print(f"  Package: [yellow]Not installed[/yellow]")
            
            if status.get("executable"):
                exe_status = status["executable"]
                if exe_status.get("available"):
                    self.console.print(f"  Executable: [green]Available[/green] ({exe_status.get('path')})")
                else:
                    self.console.print(f"  Executable: [yellow]Not found[/yellow]")
            
            if status.get("docker"):
                docker_status = status["docker"]
                if docker_status.get("available"):
                    self.console.print(f"  Docker: [green]Available[/green] ({docker_status.get('details')})")
                else:
                    self.console.print(f"  Docker: [yellow]Not available locally[/yellow]")
        
        # ML Modules
        self._print_module_table("Machine Learning Modules", self.components["ml_modules"])
        
        # Dependencies
        self.console.print("\n[bold cyan]Dependencies[/bold cyan]")
        deps_table = Table(show_header=True)
        deps_table.add_column("Package")
        deps_table.add_column("Description")
        deps_table.add_column("Status")
        deps_table.add_column("Version")
        
        for dep_name, dep_info in self.components["dependencies"].items():
            status = "[green]Installed[/green]" if dep_info["installed"] else "[red]Missing[/red]"
            version = dep_info["version"] or "N/A"
            deps_table.add_row(dep_name, dep_info["description"], status, version)
        
        self.console.print(deps_table)
        
        # Summary
        core_ok = sum(1 for m in self.components["core"] if m["status"] == "OK")
        core_total = len(self.components["core"])
        plugins_ok = len(self.components["plugins"])
        tools_ok = sum(1 for t in self.components["integrations"] if t["status"]["package"].get("installed", False) or 
                                                             t["status"]["executable"].get("available", False) or
                                                             t["status"]["docker"].get("available", False))
        tools_total = len(self.components["integrations"])
        ml_ok = sum(1 for m in self.components["ml_modules"] if m["status"] == "OK")
        ml_total = len(self.components["ml_modules"])
        deps_ok = sum(1 for _, d in self.components["dependencies"].items() if d["installed"])
        deps_total = len(self.components["dependencies"])
        
        self.console.print("\n[bold green]Summary[/bold green]")
        self.console.print(f"Core Modules: {core_ok}/{core_total}")
        self.console.print(f"Plugins: {plugins_ok}/{len(self.components['plugins'])}")
        self.console.print(f"Tool Integrations: {tools_ok}/{tools_total}")
        self.console.print(f"ML Modules: {ml_ok}/{ml_total}")
        self.console.print(f"Dependencies: {deps_ok}/{deps_total}")
        
        total_ok = core_ok + plugins_ok + tools_ok + ml_ok + deps_ok
        total_components = core_total + len(self.components["plugins"]) + tools_total + ml_total + deps_total
        
        overall_health = total_ok / total_components if total_components > 0 else 0
        health_color = "green" if overall_health >= 0.8 else "yellow" if overall_health >= 0.6 else "red"
        
        self.console.print(f"\n[bold {health_color}]Overall Health: {overall_health:.1%}[/bold {health_color}]")
        
        # Recommendations
        if overall_health < 1.0:
            self.console.print("\n[bold]Recommendations:[/bold]")
            if deps_ok < deps_total:
                self.console.print("• Install missing dependencies: [bold]poetry install[/bold]")
            if tools_ok < tools_total:
                self.console.print("• Install missing security tools or ensure Docker is available")
            if core_ok < core_total or ml_ok < ml_total:
                self.console.print("• Verify the project structure is intact")
    
    def _print_module_table(self, title, modules):
        """Print a table of module statuses."""
        self.console.print(f"\n[bold cyan]{title}[/bold cyan]")
        table = Table(show_header=True)
        table.add_column("Module")
        table.add_column("Status")
        
        for module in modules:
            status_color = "green" if module["status"] in ["OK", "DISCOVERED"] else "red"
            table.add_row(
                module["name"], 
                f"[{status_color}]{module['status']}[/{status_color}]"
            )
        
        self.console.print(table)

    def export_report(self, output_path: str) -> None:
        """Export the report data to a JSON file."""
        with open(output_path, 'w') as f:
            json.dump(self.components, f, indent=2)
        self.console.print(f"\nReport exported to [bold]{output_path}[/bold]")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate a Sniper status report")
    parser.add_argument("--export", "-e", help="Export report to JSON file", metavar="FILE")
    args = parser.parse_args()
    
    report = SniperStatusReport()
    report.generate_report()
    
    if args.export:
        report.export_report(args.export) 