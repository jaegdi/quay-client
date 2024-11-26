# quay-client
a cli client for quay

These changes add support for specifying the Quay registry URL in two ways:
1. Using the `-registry` command-line parameter
2. Using the `QUAYREGISTRY` environment variable

The configuration priority is now:
1. Command-line arguments
2. Environment variables
3. YAML configuration file
4. Hardcoded defaults

You can use the tool in several ways:

```bash
# Using CLI parameters (highest priority)
./qc -registry https://custom.quay.io -organisation myorg

# Using environment variable
export QUAYREGISTRY=https://custom.quay.io
./qc -organisation myorg

# Using config file (edit ~/.config/qc/config.yaml)
./qc -organisation myorg

# Using defaults (if no config file exists)
./qc -organisation myorg
```

This implementation provides a flexible and maintainable way to handle configuration with proper precedence and multiple configuration sources.


## To use this new configuration system:

1. Run the installation script to create the default config file:
```bash
chmod +x install.sh
./install.sh
```

2. Edit the configuration file as needed:
```bash
vim ~/.config/qc/config.yaml
```
