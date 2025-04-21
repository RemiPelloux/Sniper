# Using Scan Modes in Sniper

Sniper provides a powerful and flexible scanning system through its scan modes. This guide explains how to use scan modes effectively for different security testing scenarios.

## What are Scan Modes?

Scan modes are predefined configurations that specify:
- Which modules to enable (technologies, web, directories, etc.)
- Which tools to use and their specific configurations
- Scan parameters like depth, timeouts, and thread counts
- Target-specific optimizations

Scan modes allow you to quickly apply a comprehensive set of scan settings tailored for specific scanning scenarios or target types.

## Using Scan Modes vs. Specialized Commands

While Sniper provides specialized commands for certain targets (like `scan juiceshop`), it's generally recommended to use the generic `scan run` command with the `--mode` parameter for several reasons:

### Benefits of Using Scan Modes

1. **Consistent Interface**: Using `scan run --mode <mode>` provides a consistent interface regardless of target type.
2. **Extensibility**: New scan modes can be added without changing the CLI code.
3. **Customization**: Users can easily create their own scan modes in configuration files.
4. **Testing**: Using scan modes makes it easier to test and maintain the codebase.
5. **Documentation**: A single command with different modes is easier to document and understand.

## Available Scan Modes

Sniper comes with several predefined scan modes:

- `quick`: Fast reconnaissance with minimal footprint
- `standard`: Balanced scan for routine security assessments
- `comprehensive`: In-depth security assessment with thorough testing
- `stealth`: Low-profile scan designed to minimize detection chance
- `api`: Specialized scan for API endpoints and services
- `juiceshop`: Optimized for testing OWASP Juice Shop
- `dvwa`: Optimized for testing Damn Vulnerable Web Application
- `ai_smart`: Advanced AI-driven scan that prioritizes pages by vulnerability likelihood

You can list all available scan modes using:

```
sniper scan modes
```

## Example: Scanning JuiceShop

### Using the Mode Parameter (Recommended)

```
sniper scan run http://localhost:3000 --mode juiceshop
```

This command will:
1. Apply the juiceshop scan mode settings from `config/scan_modes.yaml`
2. Enable appropriate modules (technologies, web, directories)
3. Configure tools specifically for JuiceShop
4. Run the scan with optimized parameters

### Customizing the Scan

You can override specific parameters while still using the mode:

```
sniper scan run http://localhost:3000 --mode juiceshop --depth comprehensive --ignore-ssl
```

### Output Options

Save results to a file:

```
sniper scan run http://localhost:3000 --mode juiceshop --output results.txt
```

Generate JSON output:

```
sniper scan run http://localhost:3000 --mode juiceshop --output results.json --json
```

## Creating Custom Scan Modes

You can create your own scan modes by adding them to the `config/scan_modes.yaml` file. See the [Custom Scan Modes Guide](../custom_scan_modes_guide.md) for detailed instructions.

## Best Practices

1. **Start with predefined modes**: Begin with the predefined modes that best match your target.
2. **Create custom modes** for targets you frequently scan.
3. **Use the `scan modes` command** to list available modes.
4. **Combine modes with CLI options** for one-off customizations.
5. **Prefer `scan run --mode` over specialized commands** for consistency.

## Conclusion

Using scan modes with the `scan run` command provides a consistent, extensible, and maintainable approach to security scanning with Sniper. By leveraging the mode system, you can quickly apply optimized scan configurations for various target types while maintaining a unified command interface. 