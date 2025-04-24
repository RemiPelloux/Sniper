#!/usr/bin/env python3
"""
Tool Analysis Script

This script analyzes tool configurations in the Sniper project, categorizing them
and identifying gaps, duplicates, and other insights.
"""

import os
import sys
import yaml
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set, Tuple, Any, Optional

# Directory constants
CORE_TOOLS_DIR = "../config/tools"
CUSTOM_TOOLS_DIR = "../config/custom_tools"
OUTPUT_DIR = "../docs/reports"

def load_yaml_file(file_path: str) -> dict:
    """Load a YAML file and return its contents as a dictionary."""
    try:
        with open(file_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading {file_path}: {e}")
        return {}

def load_tools_from_directory(directory: str) -> Dict[str, dict]:
    """Load all tool configuration YAML files from a directory."""
    tools = {}
    
    # Check if directory exists
    if not os.path.exists(directory):
        print(f"Warning: Directory {directory} does not exist.")
        return tools
    
    for file in os.listdir(directory):
        if file.endswith('.yaml') or file.endswith('.yml'):
            file_path = os.path.join(directory, file)
            content = load_yaml_file(file_path)
            
            if not content:
                continue
                
            # Handle different YAML structures
            if isinstance(content, dict) and len(content) == 1 and next(iter(content.values())) is not None:
                # Structure where tool name is the top-level key
                # Example: {"subfinder": {...}}
                tool_name = next(iter(content.keys()))
                tool_config = content[tool_name]
                # Ensure the name field exists
                if 'name' not in tool_config:
                    tool_config['name'] = tool_name
                tools[tool_name] = tool_config
            else:
                # Structure where config is direct and name is a field
                # Or filename should be used as name
                tool_name = os.path.splitext(file)[0]
                if isinstance(content, dict):
                    if 'name' in content:
                        tool_name = content['name']
                    tools[tool_name] = content
                else:
                    print(f"Warning: Unexpected format in {file_path}")
    
    return tools

def get_tool_categories(config: dict) -> List[str]:
    """Extract categories from a tool config, handling different possible structures."""
    categories = []
    
    # Try different possible category fields
    if 'categories' in config and isinstance(config['categories'], list):
        categories.extend(config['categories'])
    elif 'categories' in config and isinstance(config['categories'], str):
        categories.append(config['categories'])
    elif 'category' in config and isinstance(config['category'], str):
        categories.append(config['category'])
    elif 'type' in config and isinstance(config['type'], str):
        categories.append(config['type'])
    
    # If no categories found, mark as uncategorized
    if not categories:
        categories = ['uncategorized']
    
    return categories

def categorize_tools(tools: Dict[str, dict]) -> Dict[str, List[str]]:
    """Categorize tools based on their categories field."""
    categories = defaultdict(list)
    
    for name, config in tools.items():
        tool_categories = get_tool_categories(config)
        for category in tool_categories:
            categories[category].append(name)
    
    return dict(categories)

def find_category_gaps(core_categories: Dict[str, List[str]], 
                     custom_categories: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """Find categories in core tools that have no custom tools."""
    gaps = {}
    
    for category, tools in core_categories.items():
        if category not in custom_categories or len(custom_categories[category]) == 0:
            gaps[category] = tools
    
    return gaps

def find_duplicate_tools(core_tools: Dict[str, dict], 
                        custom_tools: Dict[str, dict]) -> List[str]:
    """Find tools that exist in both core and custom configurations."""
    core_set = set(core_tools.keys())
    custom_set = set(custom_tools.keys())
    
    return list(core_set.intersection(custom_set))

def analyze_scan_modes(tools: Dict[str, dict]) -> Dict[str, List[str]]:
    """Analyze which tools are suitable for different scan modes."""
    modes = {
        'quick': [],
        'standard': [],
        'comprehensive': [],
        'stealth': [],
        'api': []
    }
    
    for name, config in tools.items():
        # Quick scan: tools with recommendation score >= 90 or fast execution time
        is_quick = False
        if 'recommendation_score' in config and isinstance(config['recommendation_score'], (int, float)) and config['recommendation_score'] >= 90:
            is_quick = True
        if 'execution_time' in config:
            exec_time = config['execution_time']
            if isinstance(exec_time, str) and exec_time.lower() in ['fast', 'quick', 'short']:
                is_quick = True
            elif isinstance(exec_time, (int, float)) and exec_time < 300:  # Less than 5 minutes
                is_quick = True
        
        if is_quick:
            modes['quick'].append(name)
        
        # Standard scan: Tools with medium execution time or recommended score
        is_standard = False
        if 'execution_time' in config:
            exec_time = config['execution_time']
            if isinstance(exec_time, str) and exec_time.lower() in ['medium', 'standard']:
                is_standard = True
            elif isinstance(exec_time, (int, float)) and 300 <= exec_time < 900:  # 5-15 minutes
                is_standard = True
        if 'recommendation_score' in config and isinstance(config['recommendation_score'], (int, float)) and config['recommendation_score'] >= 75:
            is_standard = True
        
        if is_standard:
            modes['standard'].append(name)
        
        # Comprehensive scan: all tools
        modes['comprehensive'].append(name)
        
        # Stealth scan: tools with stealth tag or passive in categories
        is_stealth = False
        if 'tags' in config and isinstance(config['tags'], list) and 'stealth' in map(str.lower, config['tags']):
            is_stealth = True
        categories = get_tool_categories(config)
        if any('passive' in category.lower() for category in categories):
            is_stealth = True
        
        if is_stealth:
            modes['stealth'].append(name)
        
        # API scan: tools with API tag or has_api field
        is_api = False
        if 'tags' in config and isinstance(config['tags'], list) and any('api' in tag.lower() for tag in config['tags']):
            is_api = True
        if 'has_api' in config and config['has_api']:
            is_api = True
        if 'api' in name.lower() or (config.get('description') and 'api' in config['description'].lower()):
            is_api = True
        if config.get('target_types') and isinstance(config['target_types'], list) and 'api' in map(str.lower, config['target_types']):
            is_api = True
        
        if is_api:
            modes['api'].append(name)
    
    return modes

def analyze_installation_methods(tools: Dict[str, dict]) -> Tuple[List[str], List[str]]:
    """Analyze which tools have installation methods defined and which don't."""
    with_installation = []
    without_installation = []
    
    for name, config in tools.items():
        # Check various possible install fields
        has_install = False
        if 'install' in config and config['install']:
            has_install = True
        elif 'installation' in config and config['installation']:
            has_install = True
        elif 'setup' in config and config['setup']:
            has_install = True
        
        if has_install:
            with_installation.append(name)
        else:
            without_installation.append(name)
    
    return with_installation, without_installation

def analyze_tool_recommendations(tools: Dict[str, dict]) -> Dict[str, List[str]]:
    """Analyze tool recommendation scores."""
    recommendation_groups = {
        'highly_recommended': [],     # 90-100
        'recommended': [],            # 75-89
        'moderately_recommended': [], # 50-74
        'low_recommendation': [],     # 25-49
        'not_recommended': [],        # 0-24
        'no_score': []                # No score provided
    }
    
    for name, config in tools.items():
        if 'recommendation_score' in config and isinstance(config['recommendation_score'], (int, float)):
            score = config['recommendation_score']
            if score >= 90:
                recommendation_groups['highly_recommended'].append(name)
            elif score >= 75:
                recommendation_groups['recommended'].append(name)
            elif score >= 50:
                recommendation_groups['moderately_recommended'].append(name)
            elif score >= 25:
                recommendation_groups['low_recommendation'].append(name)
            else:
                recommendation_groups['not_recommended'].append(name)
        else:
            recommendation_groups['no_score'].append(name)
    
    return recommendation_groups

def analyze_tool_platforms(tools: Dict[str, dict]) -> Dict[str, List[str]]:
    """Analyze tool compatibility with different platforms."""
    platforms = defaultdict(list)
    
    for name, config in tools.items():
        added_to_platform = False
        
        # Check for explicit platforms field
        if 'platforms' in config:
            if isinstance(config['platforms'], list):
                for platform in config['platforms']:
                    platforms[str(platform).lower()].append(name)
                    added_to_platform = True
            elif isinstance(config['platforms'], str):
                platforms[config['platforms'].lower()].append(name)
                added_to_platform = True
        
        # Look for platform information in install section
        if 'install' in config and isinstance(config['install'], dict):
            for key in config['install'].keys():
                if key.lower() in ['linux', 'windows', 'macos', 'darwin', 'osx', 'unix']:
                    platforms[key.lower()].append(name)
                    added_to_platform = True
        
        # If no platform info found
        if not added_to_platform:
            platforms['unknown'].append(name)
    
    return dict(platforms)

def main():
    # Create output directory if it doesn't exist
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Load tools
    core_tools = load_tools_from_directory(CORE_TOOLS_DIR)
    custom_tools = load_tools_from_directory(CUSTOM_TOOLS_DIR)
    
    print(f"\n=== TOOL ANALYSIS REPORT ===\n")
    print(f"Core tools: {len(core_tools)}")
    print(f"Custom tools: {len(custom_tools)}")
    
    # Categorize tools
    core_categories = categorize_tools(core_tools)
    custom_categories = categorize_tools(custom_tools)
    
    print("\n=== CATEGORIES ===")
    print(f"Core tool categories: {len(core_categories)}")
    for category, tools in sorted(core_categories.items()):
        print(f"  - {category}: {len(tools)} tools")
    
    print(f"\nCustom tool categories: {len(custom_categories)}")
    for category, tools in sorted(custom_categories.items()):
        print(f"  - {category}: {len(tools)} tools")
    
    # Find category gaps
    gaps = find_category_gaps(core_categories, custom_categories)
    print("\n=== CATEGORY GAPS ===")
    print(f"Categories with core tools but no custom tools: {len(gaps)}")
    for category, tools in sorted(gaps.items()):
        print(f"  - {category}: {len(tools)} core tools, 0 custom tools")
    
    # Find duplicate tools
    duplicates = find_duplicate_tools(core_tools, custom_tools)
    print("\n=== DUPLICATE TOOLS ===")
    print(f"Tools defined in both core and custom: {len(duplicates)}")
    for tool in sorted(duplicates):
        print(f"  - {tool}")
    
    # Analyze scan modes
    all_tools = {**core_tools, **custom_tools}
    scan_modes = analyze_scan_modes(all_tools)
    
    print("\n=== SCAN MODE ANALYSIS ===")
    for mode, tools in scan_modes.items():
        print(f"{mode} scan: {len(tools)} tools")
        if tools:
            sample = sorted(tools)[:5]
            print(f"  Examples: {', '.join(sample)}" + (" ..." if len(tools) > 5 else ""))
    
    # Analyze installation methods
    with_install, without_install = analyze_installation_methods(all_tools)
    print("\n=== INSTALLATION ANALYSIS ===")
    print(f"Tools with installation methods: {len(with_install)}")
    print(f"Tools without installation methods: {len(without_install)}")
    if without_install and len(without_install) <= 10:
        print("Tools lacking installation methods:")
        for tool in sorted(without_install):
            print(f"  - {tool}")
    elif without_install:
        print(f"Tools lacking installation methods: {len(without_install)} tools")
        print(f"Examples: {', '.join(sorted(without_install)[:5])} ...")
    
    # Analyze recommendation scores
    recommendation_groups = analyze_tool_recommendations(all_tools)
    print("\n=== RECOMMENDATION SCORE ANALYSIS ===")
    for group, tools in recommendation_groups.items():
        if tools:
            print(f"{group.replace('_', ' ').title()}: {len(tools)} tools")
    
    # Analyze platforms
    platforms = analyze_tool_platforms(all_tools)
    print("\n=== PLATFORM COMPATIBILITY ===")
    for platform, tools in sorted(platforms.items()):
        if platform != 'unknown' and tools:
            print(f"{platform}: {len(tools)} tools")
    
    # Generate recommendations
    print("\n=== RECOMMENDATIONS ===")
    if duplicates:
        print("1. Consider consolidating duplicate tool definitions between core and custom.")
    
    if len(gaps) > 0:
        print("2. Add custom tools for these categories with core tools: " + 
              ", ".join(sorted(gaps.keys())[:5]) + 
              (" ..." if len(gaps) > 5 else ""))
    
    if 'uncategorized' in core_categories or 'uncategorized' in custom_categories:
        print("3. Categorize all uncategorized tools.")
    
    if without_install:
        print("4. Add installation methods for tools lacking them.")
    
    if recommendation_groups['no_score']:
        print("5. Add recommendation scores for tools that don't have them.")
    
    if platforms.get('unknown', []):
        print("6. Specify platform compatibility for all tools.")
    
    # Save analysis as a report
    report_path = os.path.join(OUTPUT_DIR, "tool_analysis_report.md")
    with open(report_path, 'w') as f:
        f.write("# Sniper Tool Analysis Report\n\n")
        f.write(f"- Core tools: {len(core_tools)}\n")
        f.write(f"- Custom tools: {len(custom_tools)}\n")
        f.write(f"- Total unique tools: {len(all_tools)}\n\n")
        
        f.write("## Categories\n\n")
        f.write("| Category | Core Tools | Custom Tools |\n")
        f.write("|----------|------------|-------------|\n")
        all_categories = sorted(set(list(core_categories.keys()) + list(custom_categories.keys())))
        for category in all_categories:
            core_count = len(core_categories.get(category, []))
            custom_count = len(custom_categories.get(category, []))
            f.write(f"| {category} | {core_count} | {custom_count} |\n")
        
        f.write("\n## Scan Mode Analysis\n\n")
        f.write("| Mode | Tools | Example Tools |\n")
        f.write("|------|-------|---------------|\n")
        for mode, tools in scan_modes.items():
            examples = ", ".join(sorted(tools)[:3]) if tools else "None"
            f.write(f"| {mode} | {len(tools)} | {examples} |\n")
    
    print(f"\nAnalysis complete. Full report saved to {report_path}")

if __name__ == "__main__":
    main() 