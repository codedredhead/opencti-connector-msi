# OpenCTI Multi-Source Intelligence (MSI) Connector

This configurable OpenCTI connector ingests threat intelligence from external sources. The connector supports various intelligence types (IPs, domains, URLs, emails, file hashes) with configurable scheduling, parsing rules, TLP markings, and authentication methods.

**Single Source Architecture**: Each connector instance processes one active source at a time. The `src/config.yml` file contains a single `msi:` configuration block that defines the currently active source.

**Production Deployment**: In production environments, different source configurations are deployed as separate container instances using the same connector image.

## Configuration

The active source is configured in `src/config.yml` using a single `msi:` configuration block. Each source supports:

### Core Features
- **Configurable scheduling**: `duration_period` using ISO 8601 format (PT1H, PT12H, PT24H)
- **Client types**: `raw_text` or `html` parsing engines
- **Source types**: `ip`, `domain`, `url`, `email`, `md5`, `sha1`, `sha256`
- **TLP markings**: `clear`, `green`, `amber`, `red` classifications
- **Regex patterns**: Custom IoC extraction and validation rules
- **STIX relationships**: Configurable relationships between STIX objects
- **Scoring system**: `score` and `confidence` parameters for intelligence quality

### Example Configuration
See `src/config.yml.sample` for a full set of example configurations. A minimal example:

```yaml
msi:
  name: "example_ip_feed"
  enabled: yes
  creator: "analyst"
  score: 65
  confidence: 75
  source_type: ip
  duration_period: "PT12H"
  client_type: "raw_text"
  tlp_level: "clear"
  labels: "malicious"
  url: "https://example-ti.com/feed.txt"
  auth_type: "none"
  entity_types: "indicator,ipv4-addr"
  relationships: "based-on:indicator:ipv4-addr"
  external_ref_name: "Example Feed"
  external_ref_url: "https://example-ti.com/"
  external_ref_description: "Example threat intelligence feed"
  capture_zone: "^([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\\s*$"
  capture_regex: "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"
  capture_groups: "ip:1"
  ignore_regex: "^#.*"
```


## Build the Docker image

`docker build -t opencti-connector-msi:latest .`


## Deploy the image as an OpenCTI connector on the local machine

This repository comes with a docker-compose which will deploy OpenCTI locally:

`docker compose -f /path/to/local/repo/development/docker-compose.yml up -d`

Add the below to the `docker-compose.yml`, replacing
- CONNECTOR_ID: with a valid uuid
- /path/to/local/repo: with the path to the local repo (this is optional see below on Bind Mounts)

```yaml
  msi-connector:
    image: opencti-connector-msi:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=97ccd31e-b2a4-417c-b19f-f6ee32f9a939
      - CONNECTOR_ID="valid uuid here"
      - CONNECTOR_TYPE=EXTERNAL_IMPORT
      - CONNECTOR_NAME=Multi-Source Intelligence Connector
      - CONNECTOR_SCOPE=indicator
      - CONNECTOR_LOG_LEVEL=info
    volumes:
      - /path/to/repo:/opt/opencti-connector
    restart: always
    depends_on:
      opencti:
        condition: service_healthy
```

Then running the same `docker compose up` command.


## Entrypoint
The Docker entrypoint will execute `main.py`.

## Architecture

### Single-Source Processing Pipeline

        Source Configuration (config.yml - single msi: block)
            ↓ Factory Pattern (raw_text or html client)
        ConnectorClient (Text/HTML parser)
            ↓ HTTP GET request
        Raw Data Extraction
            ↓ Regex Parsing (capture_zone + capture_regex)
        Structured IoCs [{ip: "1.2.3.4", timestamp: "..."}]
            ↓ STIX Conversion (TLP markings + relationships)
        STIX Objects (Indicators, Observables, Relationships)
            ↓ Bundle Creation with OpenCTI custom properties
        STIX Bundle
            ↓ RabbitMQ (via helper.send_stix2_bundle)
        OpenCTI Processing

### Key Components

- **ConfigConnector**: Loads YAML configuration and manages the single active source settings
- **ConnectorTemplate**: Main orchestrator that creates client based on `client_type` setting (`raw_text` or `html`)
- **ConnectorClient**: Abstract base class with ConfigurableTextClient and ConfigurableHtmlClient implementations
- **ConverterToStix**: Transforms parsed IoCs into STIX 2.1 objects with proper TLP markings and OpenCTI custom properties

### Supported STIX Objects

**Domain Objects (SDOs):**
- Identity (organization)
- Indicator (with STIX patterns)
- Infrastructure (hosting/anonymization)
- Malware, Vulnerability, Attack Pattern

**Cyber Observables (SCOs):**
- IPv4/IPv6 Address, Domain Name, Email Address, URL, File (with hashes)

**Relationships (SROs):**
- Configurable relationships between any STIX objects (based-on, consists-of, etc.)

## get_config_variable()

Use this function to retrieve config values with environment variable overrides and fallback defaults:

```python
self.tlp_level = get_config_variable(
    "CONNECTOR_TEMPLATE_TLP_LEVEL",
    ["connector_template", "tlp_level"],
    self.load,
    default="clear",
)
```

## Quick Start for Local Development

1. **Copy sample configuration:**
   ```bash
   cp src/config.yml.sample src/config.yml
   ```

2. **Build and run with development OpenCTI:**
   ```bash
   docker build -t opencti-connector-msi:latest . && \
   docker compose -f development/docker-compose.yml up -d
   ```

3. **Access OpenCTI web interface:**
   - URL: http://localhost:8081
   - Default credentials: `admin@opencti.io` / `changeme`

4. **View connector logs:**
   ```bash
   docker compose -f development/docker-compose.yml logs msi_connector -f
   ```

## Configuration Reference

For detailed configuration documentation, see:
- [`docs/config-maintenance.md`](docs/config-maintenance.md) - Configuration parameter reference
- [`docs/STIX.md`](docs/STIX.md) - STIX object creation and compliance details
- [`docs/connector-flow.md`](docs/connector-flow.md) - Architecture and data flow
