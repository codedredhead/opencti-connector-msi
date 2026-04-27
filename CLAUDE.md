# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is an OpenCTI Multi-Source Intelligence (MSI) Connector that ingests threat intelligence from external sources and converts them into STIX 2.1 objects. The connector is written in Python and designed to run as a Docker container that processes a single threat intelligence source per instance.

**Critical Architecture Principle**: Each connector instance processes ONE source at a time. The `src/config.yml` contains a single `msi:` configuration block. In production, multiple container instances run in parallel, each with a different source configuration.

## Common Development Commands

### Docker Operations

```bash
# Build the Docker image
docker build -t opencti-connector-msi:latest .

# Run local development environment with OpenCTI
docker compose -f development/docker-compose.yml up -d

# View connector logs
docker compose -f development/docker-compose.yml logs msi_connector -f

# Stop development environment
docker compose -f development/docker-compose.yml down
```

### Configuration Setup

```bash
# Copy sample configuration (if src/config.yml doesn't exist)
cp src/config.yml.sample src/config.yml

# Test source feed manually
curl -A "OpenCTI-Connector-MSI/1.0" https://feed-url
```

### Access Local OpenCTI

- URL: http://localhost:8081
- Default credentials: `admin@opencti.io` / `changeme`

## Code Architecture

### Entry Point & Flow

1. **src/main.py** - Entry point that instantiates `ConfigConnector` and `ConnectorTemplate`, then calls `connector.run()`
2. **src/external_import_connector/config_loader.py** (`ConfigConnector`) - Loads `src/config.yml` and environment variables using `get_config_variable()` helper
3. **src/external_import_connector/connector.py** (`ConnectorTemplate`) - Main orchestrator that:
   - Creates client based on `client_type` (`raw_text` or `html`) using factory pattern
   - Calls `client.get_entities()` to fetch and parse data
   - Calls `converter.create_entities_from_source_data()` to convert to STIX objects
   - Sends STIX bundle to OpenCTI via RabbitMQ using `helper.send_stix2_bundle()`

### Key Components

**ConfigConnector** (`config_loader.py`):

- Loads single `msi:` block from `src/config.yml`
- Supports environment variable overrides (format: `MSI_PARAMETER` or nested `["msi", "parameter"]`)
- Validates regex patterns, score (0-100), and confidence (0-100) at startup
- Parses relationships string format: `"type:source:target"` (e.g., `"based-on:indicator:ipv4-addr"`)

**ConnectorTemplate** (`connector.py`):

- Factory pattern: Creates `ConfigurableTextClient` or `ConfigurableHtmlClient` based on `client_type` config
- Single-source processing: `_collect_single_source()` fetches entities from one source
- Adds metadata objects (author, TLP marking) to STIX bundle before sending

**ConnectorClient** (`client_api.py`):

- Abstract base class with two implementations:
  - `ConfigurableTextClient`: Parses plain text feeds using regex patterns (`capture_zone`, `capture_regex`, `ignore_regex`)
  - `ConfigurableHtmlClient`: Parses HTML feeds using BeautifulSoup (extracts IPs, domains, URLs, emails from anchor tags)
- Both use `requests.Session` with custom User-Agent: `"OpenCTI-Connector-MSI/1.0"`
- Regex parsing flow for text client:
  1. Filter lines with `ignore_regex` (e.g., skip comments)
  2. Match lines with `capture_zone` (defines entry boundaries)
  3. Extract indicators with `capture_regex` (e.g., IP addresses)
  4. Map capture groups using `capture_groups` (e.g., `"ip:1,timestamp:2"` maps group 1 to "ip" field)

**ConverterToStix** (`converter_to_stix.py`):

- Converts parsed entities to STIX 2.1 objects based on `entity_types` configuration
- Supported STIX Domain Objects (SDOs): Indicator, Infrastructure, Malware, Vulnerability, Attack Pattern, Identity
- Supported STIX Cyber Observables (SCOs): IPv4Address, IPv6Address, DomainName, EmailAddress, URL, File (with MD5/SHA1/SHA256 hashes)
- Supports CIDR notation for network ranges (stored as IPv4/IPv6 Address with custom properties)
- Creates relationships between STIX objects based on `relationships` config (e.g., `"based-on:indicator:ipv4-addr"`)
- Adds OpenCTI custom properties: `x_opencti_created_by_ref`, `x_opencti_labels`, `x_opencti_score`, `x_opencti_description`
- TLP markings: `clear` (WHITE), `green`, `amber`, `amber+strict`, `red`
- Validation methods: `_is_ipv4()`, `_is_ipv6()`, `_is_cidr()`, `_is_domain()`, `_is_email()`, `_is_url()`, `_is_md5()`, `_is_sha1()`, `_is_sha256()`
- URL normalization: Handles defanged URLs (e.g., `hxxp://` → `http://`), adds protocol if missing

### Configuration System

**get_config_variable() Pattern**:
The OpenCTI helper function `get_config_variable()` is used throughout `config_loader.py` to load configuration with environment variable overrides and fallback defaults:

```python
# Signature: get_config_variable(env_var_name, yaml_path, config_dict, required=True, default=None, strict=True)
self.tlp_level = get_config_variable(
    "MSI_TLP_LEVEL",                          # Environment variable name
    ["msi", "tlp_level"],                     # YAML path to value
    self.load,                                # Loaded config dictionary
    False,                                    # Not required
    "clear",                                  # Default value
    False                                     # Not strict
)
```

**Configuration Precedence**:

1. Environment variable (e.g., `MSI_TLP_LEVEL`)
2. YAML config value (e.g., `msi.tlp_level` in `src/config.yml`)
3. Default value (if provided in function call)

**Single Source Configuration Structure** (`src/config.yml`):

```yaml
msi:
  name: "source_identifier"
  enabled: yes
  creator: "username"
  score: 65                                    # 0-100
  confidence: 75                               # 0-100
  source_type: ip|domain|url|email|md5|sha1|sha256
  duration_period: "PT12H"                     # ISO 8601 format
  client_type: "raw_text"|"html"
  tlp_level: "clear"|"green"|"amber"|"red"
  labels: "malicious,sshclient"                # Comma-separated
  url: "https://threat-feed.example.com/data"
  auth_type: "none"|"api_key"|"bearer"
  entity_types: "indicator,ipv4-addr"          # Comma-separated STIX types
  relationships: "based-on:indicator:ipv4-addr"
  external_ref_name: "Source Name"
  external_ref_url: "https://source.example.com/"
  external_ref_description: "Description of source"
  capture_zone: "^\\d+\\s*\\|\\s*([0-9.]+)\\s*\\|"  # Regex for entry boundaries
  capture_regex: "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"  # Regex for extracting indicators
  capture_groups: "ip:1,timestamp:2"           # Map capture groups to fields
  ignore_regex: "^(#|ASN|$)"                   # Skip lines matching pattern
```

### Production Deployment

**Infrastructure Repository Locations**:

- Configure the path to `msi.yaml` in your infrastructure repository based on your deployment environment

**Deployment Model**:

- Each source listed in `msi.yaml` spawns a dedicated container instance via Terraform
- Multiple sources run in parallel as separate containers, all using the same Docker image
- Each container has its own configuration passed via environment variables
- Single source configuration per container (set via `MSI_*` environment variables)

**Container Specification**:

- Base image: `python:3.12-alpine`
- Dependencies: Installed from `src/requirements.txt` (pycti, pyyaml, requests, validators, beautifulsoup4)
- Entrypoint: `/entrypoint.sh` → executes `src/main.py`
- Environment variables:
  - OpenCTI connection: `OPENCTI_URL`, `OPENCTI_TOKEN`
  - Connector metadata: `CONNECTOR_ID`, `CONNECTOR_TYPE`, `CONNECTOR_NAME`, `CONNECTOR_SCOPE`, `CONNECTOR_LOG_LEVEL`
  - Source configuration: `MSI_NAME`, `MSI_URL`, `MSI_CLIENT_TYPE`, `MSI_SOURCE_TYPE`, `MSI_TLP_LEVEL`, etc.

## Important Implementation Details

### Regex Pattern Usage

- All regex patterns are validated at startup in `config_loader.py`
- **Raw text parsing flow** (`ConfigurableTextClient`):
  1. `ignore_regex` filters out unwanted lines (e.g., comments starting with `#`)
  2. `capture_zone` defines boundaries of an entry (must use capture groups if extracting structured data)
  3. `capture_regex` extracts specific indicators from matched entries
  4. `capture_groups` maps regex capture groups to entity fields (format: `"field:group_index"`, 1-indexed)

### STIX Object Creation

- Indicators require valid STIX patterns (e.g., `[ipv4-addr:value = '1.2.3.4']`)
- All objects get TLP marking refs from source config
- Creator ID is deterministic: `Identity.generate_id(name=creator_name, identity_class="individual")`
- Author identity is organization-level: `Identity.generate_id(name=org_name, identity_class="organization")`
- Relationships are created in second pass after all entities exist (prevents missing reference errors)

### Data Flow & RabbitMQ

1. Connector fetches data via HTTP GET request
2. Client parses data into entities (list of dicts with `observable_value` key)
3. Converter transforms entities into STIX objects
4. Bundle created with `helper.stix2_create_bundle(stix_objects)`
5. Bundle sent to RabbitMQ with `helper.send_stix2_bundle(bundle, work_id=work_id, cleanup_inconsistent_bundle=True)`
6. OpenCTI workers consume from RabbitMQ and process into platform

### Logging Conventions

- Use structured logging: `self.helper.connector_logger.info("message", {"key": "value"})`
- Log levels: `debug`, `info`, `warning`, `error`
- Prefix all MSI connector logs with `[MSI]` for easy filtering
- Log entity counts, HTTP response metrics, and relationship creation for debugging

### File Structure

```tree
src/
├── config.yml                          # Single source configuration
├── main.py                             # Entry point
├── requirements.txt                    # Python dependencies
└── external_import_connector/
    ├── __init__.py
    ├── client_api.py                   # HTTP client implementations
    ├── config_loader.py                # Configuration loading
    ├── connector.py                    # Main orchestrator
    ├── converter_to_stix.py            # STIX object creation
    ├── supported_types.py              # Enum of supported source types
    └── utils.py                        # Helper functions (IP detection, HTML parsing)
```

## Testing New Sources

1. **Inspect the feed**: Use curl to examine raw feed data

   ```bash
   curl -A "OpenCTI-Connector-MSI/1.0" https://feed-url
   ```

2. **Test regex patterns**: Use online validators (regex101.com) with sample feed data
3. **Update configuration**: Edit `src/config.yml` with new source configuration
4. **Build and run locally**:

   ```bash
   docker build -t opencti-connector-msi:latest . && \
   docker compose -f development/docker-compose.yml up -d
   ```

5. **Monitor logs**: Watch for parsing success/failures

   ```bash
   docker compose -f development/docker-compose.yml logs msi_connector -f
   ```

6. **Verify in UI**: Check OpenCTI at <http://localhost:8081> → Data → Indicators
7. **Check warnings**: Look for content-type mismatches (feed should return `text/plain` for raw text, not `text/html` or `application/json`)

## Common Issues

**No entities extracted**:

- Check `capture_regex` matches expected data format
- Ensure `ignore_regex` isn't filtering out valid data
- Verify `capture_zone` encompasses target data (for text feeds)
- Check if URL returns HTML/JSON instead of raw text (warning logged)

**Regex compilation errors**:

- Test patterns in online validators
- Ensure proper escaping in YAML (use single quotes or escape backslashes: `\\d+`)
- Check capture group numbering matches `capture_groups` mapping

**Invalid STIX patterns**:

- Verify `source_type` matches actual data (e.g., don't use `source_type: domain` for IP addresses)
- Check validation methods in `converter_to_stix.py` (e.g., `_is_ipv4()`, `_is_domain()`)
- Review STIX pattern format in logs

## Related Documentation

- `docs/config-maintenance.md` - Detailed configuration parameter reference
- `docs/STIX.md` - STIX object creation and compliance details (if exists)
- `docs/connector-flow.md` - Architecture and data flow diagrams (if exists)
- `README.md` - Overview, deployment instructions, and quick start guide
