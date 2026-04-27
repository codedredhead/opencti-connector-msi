# Configuration Management Guide

This document serves as guidance for understanding the MSI connector's configuration management file, `msi.yaml`.

## Overview

The MSI connector uses different configuration approaches depending on the deployment environment:

### Local Development

- Uses `src/config.yml` file (copied from `src/config.yml.sample`)
- For local testing and development work only
- Processes a single `msi:` configuration block

### Development and Production Environments

- Uses `msi.yaml` managed by your infrastructure tooling (e.g., Terraform)
- **One connector instance per source**: Each source in `msi.yaml` spawns a dedicated container instance
- Allows parallel processing of multiple threat intelligence sources

## Configuration Structure

```yaml
# Multi-Source Intelligence Connector Configuration
# NOTE: Only 1 msi source will be active at a time
# This file defines the active source and how its data will be transformed into STIX 2.1 compliant objects.

msi:
  name: "source_identifier"
  enabled: yes|no
  creator: "username"
  score: 60
  confidence: 75
  source_type: ip|email|domain|url|md5|sha1|sha256
  duration_period: "PT12H"
  # ... additional source-specific configuration
```

## Source Configuration Parameters

### Required Parameters

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `name` | string | Human-readable name for the source | `"dataplane_sshclient"` |
| `enabled` | boolean | Whether this source should be processed | `yes` |
| `creator` | string | Username of the configuration creator | `"analyst"` |
| `source_type` | string | Type of indicators being processed | `"ip"`, `"domain"`, `"url"`, `"sha1"`, `"SHA265"`, `"MD5"` |
| `url` | string | URL to fetch threat intelligence data | `"https://dataplane.org/sshclient.txt"` |
| `client_type` | string | Type of client parser to use | `"raw_text"`, `"html"` |

### Core Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `score` | integer | `60` | Confidence score for the source (0-100), defaults to 50 |
| `confidence` | integer | `75` | Confidence level for indicators from this source (0-100), defaults to 50 |
| `duration_period` | string | `"PT24H"` | How often to poll this source (ISO 8601 duration format) |
| `tlp_level` | string | `"clear"` | Traffic Light Protocol marking level (`clear`, `green`, `amber`, `red`) |
| `labels` | string | `""` | Comma-separated labels to apply to indicators |
| `auth_type` | string | `"none"` | Authentication method (`none`, `api_key`, `bearer`) |

### STIX Entity Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `entity_types` | string | `"indicator"` | Comma-separated STIX entity types to create |
| `relationships` | string | `""` | Relationships between entities in format `"type:source:target"` |

**Supported Entity Types:**

- `indicator` - STIX Indicator objects
- `ipv4-addr` - IPv4 Address objects
- `ipv6-addr` - IPv6 Address objects
- `domain-name` - Domain Name objects
- `email-addr` - Email Address objects
- `url` - URL objects
- `file` - File objects (for hash-based sources (SHA1, SHA256, MD5))
- `infrastructure` - Infrastructure objects
- `malware` - Malware objects
- `vulnerability` - Vulnerability objects
- `attack-pattern` - Attack Pattern objects

**Relationship Format:**

```yaml
relationships: "based-on:indicator:ipv4-addr,consists-of:infrastructure:ipv4-addr"
```

### External Reference Configuration

| Parameter | Type | Description |
| ----------- | ------ | ------------- |
| `external_ref_name` | string | Name of the external reference |
| `external_ref_url` | string | URL of the external reference |
| `external_ref_description` | string | Description of the external reference |

### Data Parsing Configuration

| Parameter | Type | Description |
| ----------- | ------ | ------------- |
| `capture_zone` | string | Regex to define the zone containing data to extract |
| `capture_regex` | string | Regex to extract specific data patterns |
| `capture_groups` | string | Named capture groups mapping (e.g., `"ip:1,timestamp:2"`) |
| `ignore_regex` | string | Regex patterns to ignore/skip |

### Authentication Configuration

| Parameter | Type | Description |
| ----------- | ------ | ------------- |
| `auth_token_env` | string | Environment variable containing auth token |
| `auth_key_env` | string | Environment variable containing API key |
| `auth_header` | string | HTTP header name for authentication |

## Duration Period Format

Duration periods use ISO 8601 format with the following supported units:

- `PT1H` - 1 hour - poll every hour
- `PT30M` - 30 minutes - poll every 30 min
- `PT1H30M` - 1 hour 30 minutes - poll every 1.5 hrs
- `PT24H` - 24 hours - poll every 24 hr

## Client Types

### raw_text

For plain text sources containing IP addresses or other indicators.

**Configuration Example:**

```yaml
client_type: "raw_text"
capture_regex: "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"
ignore_regex: "^#.*"
```

### html

For HTML sources where data needs to be extracted from web pages.

**Configuration Example:**

```yaml
client_type: "html"
capture_zone: "\\b([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\\b"
```

## Environment Variable Overrides

Any configuration parameter can be overridden using environment variables with the format:

```config
CONNECTOR_SOURCE_{SOURCE_NAME}_{PARAMETER}
```

**Examples:**

- `CONNECTOR_SOURCE_TOR_PROJECT_ENABLED=false`
- `CONNECTOR_SOURCE_FIREHOL_CRYPTOWALL_DURATION_PERIOD=PT6H`
- `CONNECTOR_SOURCE_CYBERCRIME_URL=https://custom-url.com/data`

## Example Configurations

### Basic IP List Source

```yaml
msi:
  name: "basic_ip_blocklist"
  enabled: yes
  creator: "analyst"
  score: 70
  confidence: 80
  source_type: ip
  duration_period: "PT24H"
  client_type: "raw_text"
  tlp_level: "clear"
  labels: "malicious-activity"
  url: "https://example-ti.com/ips.txt"
  auth_type: "none"
  entity_types: "indicator,ipv4-addr"
  relationships: "based-on:indicator:ipv4-addr"
  external_ref_name: "Basic IP Blocklist"
  external_ref_url: "https://example-ti.com/"
  external_ref_description: "Example TI provides basic IP blocklist for malicious IPv4 addresses"
  capture_zone: "^([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\\s*$"
  capture_regex: "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"
  capture_groups: "ip:1"
  ignore_regex: "^#.*"
```

## Adding New Sources

- #TODO

### Local (Development)

1. **Replace existing configuration** with new `msi:` block in `config.yml` (only one active source at a time)
2. **Test regex patterns** using the built-in validation (check connector logs)
3. **Verify authentication** if using API keys or tokens
4. **Set appropriate TLP marking** based on data sensitivity
5. **Configure duration period** based on data freshness requirements
6. **Test the source** by enabling it and monitoring connector logs

### Production Environments

1. **Add new source** to your `msi.yaml` in your infrastructure configuration
2. **Deploy** - each source will get its own container instance
3. **Monitor deployment** - multiple sources run in parallel automatically
4. **Test source independently** - each instance has its own logs and state

## Troubleshooting

### Common Issues

**Regex Compilation Errors:**

- Check that regex patterns are properly escaped
- Test patterns using online regex validators
- Ensure capture groups are properly numbered

**No Data Extracted:**

- Verify config syntax
- Verify `capture_regex` matches the expected data format
- Check that `ignore_regex` isn't filtering out valid data
- Ensure `capture_zone` encompasses the target data

### Validation

The connector validates regex patterns during startup. Check logs for messages like:

```config
source_name: capture_regex compiled successfully
source_name: INVALID capture_zone: 'pattern' - error message
```

### Testing Sources

1. **Enable single source** for testing
2. **Check connector logs** for parsing success/failure
3. **Verify data in OpenCTI** after successful ingestion
4. **Monitor performance** impact of new sources

## Best Practices

- **Use descriptive names** that clearly identify the threat intelligence source
- **Set appropriate TLP markings** based on data sensitivity and sharing restrictions
- **Choose optimal polling frequencies** to balance freshness with resource usage
- **Include external references** for attribution and additional context
- **Test regex patterns** thoroughly before deploying to production (CURL is your friend)
- **Monitor source reliability** and disable problematic sources promptly
