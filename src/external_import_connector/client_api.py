import os
import re
import json
from abc import ABC, abstractmethod
import requests
from bs4 import BeautifulSoup

from .utils import extract_domains_from_html,extract_ips,extract_urls_from_html,calculate_response_metrics
from .supported_types import SupportedType

class ConnectorClient(ABC):
    """Abstract base class for source-specific clients"""

    def __init__(self, helper, source_config):
        self.helper = helper
        self.config = source_config
        self.session = requests.Session()
        # self._setup_authentication()

        """
        Set user agent
        <product>/<product-version>
        """
        self.session.headers.update({
            "User-Agent": f"OpenCTI-Connector-MSI/1.0"
        })

    # def _setup_authentication(self):
    #     """
    #     Setup authentication based on source configuration.
    #     Not currently supported by the config.
    #     """
    #     if self.config.auth_type == "bearer" and self.config.auth_token_env:
    #         token = os.getenv(self.config.auth_token_env)
    #         if token:
    #             self.session.headers.update({"Authorization": f"Bearer {token}"})
    #     elif self.config.auth_type == "api_key" and self.config.auth_key_env:
    #         api_key = os.getenv(self.config.auth_key_env)
    #         if api_key:
    #             self.session.headers.update({self.config.auth_header: api_key})

    def _request_data(self, api_url: str, params=None):
        """
        Internal method to handle API requests
        :return: Response object or None if error
        """
        try:
            response = self.session.get(api_url, params=params)

            self.helper.connector_logger.info(
                f"[MSI] HTTP Get Request to endpoint",
                {"url_path": api_url}
            )

            response.raise_for_status()

            # Add response size logging right after successful response
            response_metrics = calculate_response_metrics(response)
            response_metrics["url_path"] = api_url

            self.helper.connector_logger.info(
                f"[MSI] Response received from source",
                response_metrics
            )

            # Check if response contains non-raw text content
            content_type = response.headers.get('content-type', '').lower()
            if ('text/html' in content_type or
                'application/json' in content_type or
                'application/xml' in content_type or
                'text/xml' in content_type):
                self.helper.connector_logger.warning(
                    f"[MSI] URL returns {content_type} instead of raw text. "
                    f"This may cause entity extraction issues. Expected: text/plain or similar raw text format."
                )

            return response

        except requests.RequestException as err:
            self.helper.connector_logger.error(
                f"[MSI] Error while fetching data",
                {"url_path": api_url, "error": str(err)}
            )
            return None

    @abstractmethod
    def get_entities(self, params=None) -> list:
        """Retrieve entities from the data source"""
        pass


class ConfigurableTextClient(ConnectorClient):
    """Client for text-based feeds via regex parsing as defined in ../src/config.yml"""

    def get_entities(self, params=None) -> list:
        """
        Retrieve entities from text-based feed using configured regexes
        """
        try:
            url = self.config.url
            response = self._request_data(url, params)

            if not response:
                return []

            entities = []
            lines = response.text.strip().split('\n')

            # Filter out ignored lines if ignore_regex is configured
            if hasattr(self.config, 'ignore_regex') and self.config.ignore_regex:
                try:
                    ignore_pattern = re.compile(self.config.ignore_regex)
                    self.helper.connector_logger.debug(
                        f"[MSI] Compiled ignore_regex successfully"
                    )
                    lines = [line for line in lines if not ignore_pattern.match(line)]
                except re.error as e:
                    self.helper.connector_logger.error(
                        f"[MSI] INVALID ignore_regex pattern: '{self.config.ignore_regex}' - {str(e)}"
                    )
                    raise

            # Use regex patterns as defined in ../src/config.yml
            if self.config.capture_zone:
                try:
                    entry_pattern = re.compile(self.config.capture_zone, re.MULTILINE)
                    self.helper.connector_logger.debug(
                        f"[MSI] Compiled capture_zone successfully"
                    )
                except re.error as e:
                    self.helper.connector_logger.error(
                        f"[MSI] INVALID capture_zone pattern: '{self.config.capture_zone}' - {str(e)}"
                    )
                    raise

                for line in lines:
                    match = entry_pattern.match(line)
                    if match:
                        entity_data = {}
                        groups = match.groups()

                        # If entry has groups, create a structured entity
                        if groups:
                            entity_data = {
                                'raw_entry': line,
                                'groups': groups
                            }

                            # Parse capture groups if configured
                            if hasattr(self.config, 'capture_groups') and self.config.capture_groups:
                                group_mappings = {}
                                for mapping in self.config.capture_groups.split(','):
                                    if ':' in mapping:
                                        field, group_idx = mapping.strip().split(':')
                                        try:
                                            # Convert to 0 git based index
                                            group_idx = int(group_idx) - 1
                                            if 0 <= group_idx < len(groups):
                                                group_mappings[field] = groups[group_idx]
                                        except (ValueError, IndexError):
                                            continue
                                entity_data.update(group_mappings)
                        else:
                            entity_data = {'raw_entry': line}

                        # Extract indicators if indicator regex is configured
                        if self.config.capture_regex:
                            try:
                                match_pattern = re.compile(self.config.capture_regex)
                                matches = match_pattern.findall(line)
                                if matches:
                                    entity_data['indicators'] = matches
                                    # Use first indicator as primary observable
                                    entity_data['observable_value'] = matches[0]

                                    # Add IP format detection for ip source_type
                                    if self.config.source_type == 'ip':
                                        from .utils import detect_ip_format
                                        entity_data['ip_format'] = detect_ip_format(matches[0])
                            except re.error as e:
                                self.helper.connector_logger.error(
                                    f"[MSI] INVALID capture_regex pattern: '{self.config.capture_regex}' - {str(e)}"
                                )
                                raise

                        entities.append(entity_data)
                # When no entry regex configured - return empty to prevent dirty data
            else:
                self.helper.connector_logger.error(
                    f"[MSI] No capture_zone configured for text feed."
                    "Skipping processing to prevent invalid data entry."
                )
                return []

            self.helper.connector_logger.info(
                f"[MSI] Retrieved {len(entities)} entities from text feed"
            )

            return entities

        except Exception as err:
            self.helper.connector_logger.error(
                f"[MSI] Error fetching text feed: {err}"
            )
            return []


class ConfigurableHtmlClient(ConnectorClient):
    """Client for HTML-based feeds via BeautifulSoup parsing as defined in ../src/config.yml"""

    def get_entities(self, params=None) -> list:
        """
        Retrieve entities from HTML-based feed using BeautifulSoup parsing
        """
        try:
            url = self.config.url
            source_type= self.config.source_type
            response = self._request_data(url, params)

            if not response:
                return []

            entities = []
            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract IP addresses from anchor tags
            # Pattern: <a href="..." title="IP_ADDRESS">IP_ADDRESS</a>
            # Pattern: <a href="..." title="EMAIL_ADDRESS">EMAIL_ADDRESS</a>
            links = soup.find_all('a', href=True)
            supported_types = [item.value for item in SupportedType]
            # ensure feed is a supported type
            if source_type not in supported_types:
                self.helper.connector_logger.error(
                    f"[MSI] Unsupported source_type: '{source_type}'"
                )
                return []
            # ensure capture_regex is set
            if not (hasattr(self.config, 'capture_regex') and self.config.capture_regex):
                self.helper.connector_logger.error(
                    f"[MSI] capture_regex required for source_type '{source_type}' but not configured"
                )
                return []
            # else:
            #     regex = self.config.capture_regex

            # Handle different source types with appropriate extraction methods
            if source_type==SupportedType.DOMAIN.value:
                entities=extract_domains_from_html(self.config,response.text)
            elif source_type==SupportedType.URL.value:
                entities=extract_urls_from_html(self.config,response.text)
            else:
                # Enhanced IP extraction for mixed formats
                if source_type == SupportedType.IP.value:
                    from .utils import extract_mixed_ips
                    entities = extract_mixed_ips(links, self.config, self.helper)
                else:
                    # TODO: Rename the method
                    # Will extract more than IPv4 & IPv6
                    entities = extract_ips(links, self.config, self.helper)

            self.helper.connector_logger.info(
                f"[MSI] Retrieved {len(entities)} entities from HTML feed"
            )

            return entities

        except Exception as err:
            self.helper.connector_logger.error(
                f"[MSI] Error fetching HTML feed: {err}"
            )
            return []
