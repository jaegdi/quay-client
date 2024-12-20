# quay-client
a cli client for quay

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

# Create a config file:  qc -cc
# Using config file (edit ~/.config/qc/config.yaml)
./qc -organisation myorg

# Using defaults (if no config file exists)
./qc -organisation myorg
```

This implementation provides a flexible and maintainable way to handle configuration with proper precedence and multiple configuration sources.

You can specify the organization in multiple ways:

1. Command line:
```bash
./qc -organisation myorg   or   ./qc -o myorg
```

2. Environment variable:
```bash
export QUAYORG=myorg
./qc
```

3. Configuration file:
```yaml
registry:
  organisation: myorg
  ...
```

The priority remains:
1. Command-line arguments
2. Environment variables
3. YAML configuration file
4. Hardcoded defaults

This provides a flexible way to specify the organization while maintaining backward compatibility with the existing implementation.


## To use this new configuration system:

1. Run the installation script to create the default config file:
```bash
./qc -cc
```

2. Edit the configuration file as needed:
```bash
vim ~/.config/qc/config.yaml
```

# Build

## Compile qc client

```sh
use the provides script build.sh

./build.sh
```

## compile linux and windows verson and upload both to artifactory

```sh
./deploy-.to-.artifactory.sh
```
