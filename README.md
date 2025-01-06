# quay-client

a cli client for quay

The Quay Client Command Line Tool (qc) allows you to interact with the Quay registry.
You can perform various operations such as listing organizations, repositories, and tags,
deleting tags, and retrieving user information.

## Usage

! If the credentials for quay registry schould be used from openshift secret, it is neccessary to be logged in into cid-cluster, where a secret is in the scp-build namespace !

The default output format is yaml, option with param -ft it is text, or with -fj it is json.

### List all organisations of the quay registry as text list
```bash
qc -tf
```

### List all repositories of a existing organisation as text list
```bash
qc -o pkp -ft
```

### List from each repository of an organisation the newest tag with its highest rated vulnerability
```bash
qc -o pkp -i -ft
```

### List a tag of a repository with all vulnerabilities as yaml
```bash
qc -o pkp -i -r beratungdirekt-service -t 2.13.3-0
```

## Installation

Copy the qc binary (statically linked go binary) into a directory of your exeec path.


## Configuration

The configuration priority is:
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


### To use the configuration system:

1. Run the installation script to create the default config file:
```bash
./qc -cc
```

2. Edit the configuration file as needed:
```bash
vim ~/.config/qc/config.yaml
```

## Build

### Compile qc client

```sh
use the provides script build.sh

./build.sh
```

### compile linux and windows verson and upload both to artifactory

This is only working in our company

```sh
./deploy-to-artifactory.sh
```
