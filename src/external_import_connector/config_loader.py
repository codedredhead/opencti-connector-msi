import os
import re
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Optional

import yaml
from pycti import get_config_variable

class ConfigConnector:
    def __init__(self):
        """
        Initialize the connector with necessary configurations
        """
        self.load = self._load_config()
        self._initialize_configurations()
        # self.sources = self._initialize_sources()

    @staticmethod
    def _load_config() -> dict:
        """
        Load the configuration from the YAML file
        :return: Configuration dictionary
        """
        config_file_path = Path(__file__).parents[1].joinpath("config.yml")
        if os.path.isfile(config_file_path):
            with open(config_file_path, "r") as f:
                config = yaml.safe_load(f) or {}  # <-- returns {} if file is empty
        else:
            config = {}

        return config

    def _initialize_configurations(self) -> None:
        """
        Connector configuration variables
        :return: None
        """
        # OpenCTI configurations
        # self.name = get_config_variable(
        #     "MSI_NAME",
        #     ["msi", "name", "msi_name"],
        #     self.load
        # )

        # self.source_name = self.name.lower().replace(" ", "_").replace("-", "_")

        self.creator = get_config_variable(
            "MSI_CREATOR", ["msi", "creator", "msi_creator"],
            self.load
        )

        self.tlp_level = get_config_variable(
            "MSI_TLP_LEVEL",
            ["msi", "tlp_level", "msi_tlp_level"],
            self.load
        )

        labels_str = get_config_variable(
            "MSI_LABELS",
            ["msi", "labels", "msi_labels"],
            self.load
        )
        self.labels = [label.strip() for label in labels_str.split(",") if label.strip()]

        self.client_type = get_config_variable(
            "MSI_CLIENT_TYPE",
            ["msi", "client_type", "msi_client_type"],
            self.load
        )

        self.source_type = get_config_variable(
            "MSI_SOURCE_TYPE",
            ["msi", "source_type", "msi_source_type"],
            self.load
        )

        self.url = get_config_variable(
            "MSI_URL",
            ["msi", "url", "msi_url"],
            self.load
        )

        self.auth_type = get_config_variable(
            "MSI_AUTH_TYPE",
            ["msi", "auth_type", "msi_auth_type"],
            self.load
        )

        self.auth_token_env = get_config_variable(
            "MSI_AUTH_TOKEN_ENV",
            ["msi", "auth_token_env", "msi_auth_token_env"],
            self.load,
            False,
            "",
            False
        )

        self.auth_key_env = get_config_variable(
            "MSI_AUTH_KEY_ENV",
            ["msi", "auth_key_env", "msi_auth_key_env"],
            self.load,
            False,
            "",
            False
        )

        self.auth_header = get_config_variable(
            "MSI_AUTH_HEADER",
            ["msi", "auth_header", "msi_auth_header"],
            self.load,
            False,
            "",
            False
        )

        self.api_format = get_config_variable(
            "MSI_API_FORMAT",
            ["msi", "api_format", "msi_api_format"],
            self.load,
            False,
            "",
            False
        )

        entity_types_str = get_config_variable(
            "MSI_ENTITY_TYPES",
            ["msi", "entity_types", "msi_entity_types"],
            self.load
        )
        self.entity_types = [et.strip() for et in entity_types_str.split(",") if et.strip()]


        relationships_str = get_config_variable(
            "MSI_RELATIONSHIPS",
            ["msi", "relationships", "msi_relationships"],
            self.load
        )
        self.relationships = self._parse_relationships(relationships_str)

        self.external_ref_name = get_config_variable(
            "MSI_EXTERNAL_REF_NAME",
            ["msi", "external_ref_name", "msi_external_ref_name"],
            self.load
        )

        self.external_ref_url = get_config_variable(
            "MSI_EXTERNAL_REF_URL",
            ["msi", "external_ref_url", "msi_external_ref_url"],
            self.load
        )

        self.external_ref_description = get_config_variable(
            "MSI_EXTERNAL_REF_DESCRIPTION",
            ["msi", "external_ref_description", "msi_external_ref_description"],
            self.load
        )

        self.capture_zone = get_config_variable(
            "MSI_CAPTURE_ZONE",
            ["msi", "capture_zone", "msi_capture_zone"],
            self.load
        )

        self.capture_regex = get_config_variable(
            "MSI_CAPTURE_REGEX",
            ["msi", "capture_regex", "msi_capture_regex"],
            self.load
        )

        self.ignore_regex = get_config_variable(
            "MSI_IGNORE_REGEX",
            ["msi", "ignore_regex", "msi_ignore_regex"],
            self.load
        )

        self.capture_groups = get_config_variable(
            "MSI_CAPTURE_GROUPS",
            ["msi", "capture_groups", "msi_capture_groups"],
            self.load
        )

        self.text_entry_regex = get_config_variable(
            "MSI_TEXT_ENTRY_REGEX",
            ["msi", "text_entry_regex", "msi_text_entry_regex"],
            self.load
        )

        self.text_ip_regex = get_config_variable(
            "MSI_TEXT_IP_REGEX",
            ["msi", "text_ip_regex", "msi_text_ip_regex"],
            self.load
        )

        self.source_type = get_config_variable(
            "MSI_SOURCE_TYPE",
            ["msi", "source_type", "msi_source_type"],
            self.load
        )

        self.score = get_config_variable(
            "MSI_SCORE",
            ["msi", "score", "msi_score"],
            self.load,
            False,
            50,  # default score
            False
        )

        self.confidence = get_config_variable(
            "MSI_CONFIDENCE",
            ["msi", "confidence", "msi_confidence"],
            self.load,
            False,
            50,  # default confidence
            False
        )


        # Validate regex patterns, score, and confidence during configuration loading
        self._validate_regex_patterns()
        self._validate_score()
        self._validate_confidence()


    def _parse_relationships(self, relationships_str: str) -> list:
        """Parse relationship string format into list of dicts"""
        relationships = []
        if not relationships_str:
            return relationships

        for rel in relationships_str.split(","):
            parts = rel.strip().split(":")
            if len(parts) == 3:
                relationships.append({
                    "type": parts[0].strip(),
                    "source": parts[1].strip(),
                    "target": parts[2].strip()
                })
        return relationships

    def _validate_regex_patterns(self) -> None:
        """Validate regex patterns during configuration loading"""
        patterns_to_check = [
            ('capture_zone', self.capture_zone),
            ('capture_regex', self.capture_regex),
            ('ignore_regex', self.ignore_regex),
            ('text_entry_regex', self.text_entry_regex),
            ('text_ip_regex', self.text_ip_regex)
        ]

        for pattern_name, pattern_value in patterns_to_check:
            if pattern_value:
                try:
                    re.compile(pattern_value)
                except re.error as e:
                    raise ValueError(f"Invalid {pattern_name} for source MSI: {str(e)}")

    def _validate_score(self) -> None:
        """Validate score is within 0-100 range"""
        try:
            score_int = int(self.score)
            if not 0 <= score_int <= 100:
                raise ValueError(f"Score must be between 0-100, got: {score_int}")
            self.score = score_int
        except (ValueError, TypeError) as e:
            raise ValueError(f"Invalid score for source MSI: {str(e)}")

    def _validate_confidence(self) -> None:
        """Validate confidence is within 0-100 range"""
        try:
            confidence_int = int(self.confidence)
            if not 0 <= confidence_int <= 100:
                raise ValueError(f"Confidence must be between 0-100, got: {confidence_int}")
            self.confidence = confidence_int
        except (ValueError, TypeError) as e:
            raise ValueError(f"Invalid confidence for source MSI: {str(e)}")

    @property
    def external_references(self) -> list:
        """Generate external references list"""
        refs = []
        if self.external_ref_name and self.external_ref_url:
            ref = {
                "source_name": self.external_ref_name,
                "url": self.external_ref_url
            }
            if self.external_ref_description:
                ref["description"] = self.external_ref_description
            refs.append(ref)
        return refs
