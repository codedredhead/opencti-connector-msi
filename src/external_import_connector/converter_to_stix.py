import ipaddress
from datetime import datetime

import stix2
import validators
from pycti import Identity, MarkingDefinition, StixCoreRelationship


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper, source_config):
        self.helper = helper
        self.config = source_config

        # Get TLP level from source configuration
        tlp_level = getattr(source_config, 'tlp_level', 'amber')
        self.tlp_marking = self._create_tlp_marking(level=tlp_level.lower())

        self.author = self.create_author()
        # Generate deterministic creator ID for audit purposes without creating object
        creator_name = getattr(source_config, 'creator', 'unknown-user')
        self.creator_id = Identity.generate_id(name=creator_name, identity_class="individual")

    def create_author(self) -> dict:
        """
        Create Author identity from source configuration
        :return: Author in Stix2 object
        """
        org_name = self.config.external_ref_name

        author = stix2.Identity(
            id=Identity.generate_id(name=org_name, identity_class="organization"),
            name=org_name,
            identity_class="organization",
            description=self.config.external_ref_description or f"Threat intelligence source: {org_name}",
            object_marking_refs=[self.tlp_marking.id],
            external_references=[
                stix2.ExternalReference(**ref) for ref in self.config.external_references
            ] if self.config.external_references else None
        )
        return author


    @staticmethod
    def _create_tlp_marking(level):
        mapping = {
            "white": stix2.TLP_WHITE,
            "clear": stix2.TLP_WHITE,
            "green": stix2.TLP_GREEN,
            "amber": stix2.TLP_AMBER,
            "amber+strict": stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                custom_properties={
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:AMBER+STRICT",
                },
            ),
            "red": stix2.TLP_RED,
        }
        return mapping[level]

    def create_relationship(
        self, source_id: str, relationship_type: str, target_id: str
    ) -> dict:
        """
        Creates Relationship object
        :input source_id: ID of source in string
        :input relationship_type: Relationship type in string
        :input target_id: ID of target in string
        :return: Relationship STIX2 object
        """
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, source_id, target_id
            ),
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.creator_id,
            object_marking_refs=[self.tlp_marking.id],
        )
        return relationship

    @staticmethod
    def _is_ipv6(value: str) -> bool:
        """
        Determine whether the provided IP string is IPv6
        :input value: Value in string
        :return: A boolean
        """
        try:
            ipaddress.IPv6Address(value)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def _is_ipv4(value: str) -> bool:
        """
        Checking provided IP string is IPv4
        :input value: Value in string
        :return: A boolean
        """
        try:
            ipaddress.IPv4Address(value)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def _is_cidr(value: str) -> bool:
        """
        Check if value is in CIDR notation
        :input value: Value in string
        :return: A boolean
        """
        try:
            ipaddress.ip_network(value, strict=False)
            return '/' in value
        except (ipaddress.AddressValueError, ValueError):
            return False

    @staticmethod
    def _is_domain(value: str) -> bool:
        """
        Valid domain name regex including internationalized domain name
        :input value: Value in string
        :return: A boolean
        """
        is_valid_domain = validators.domain(value)

        if is_valid_domain:
            return True
        else:
            return False

    @staticmethod
    def _is_email(value: str) -> bool:
        """
        Valid email regex
        :input value: Value in string
        :return: A boolean
        """
        is_valid_email = validators.email(value)

        if is_valid_email:
            return True
        else:
            return False

    @staticmethod
    def _is_url(value: str) -> bool:
        """
        Valid URL regex with automatic protocol detection
        :input value: Parsed URL string
        :return: bool
        """
        if not value:
            return False

        # Clean up the value
        cleaned_value = value.strip()

        # Remove brackets that might be used for defanging
        cleaned_value = cleaned_value.replace('[', '').replace(']', '')

        # Skip if it looks like just a file path
        if '/' in cleaned_value and not ('.' in cleaned_value or ':' in cleaned_value):
            return False

        # Try as-is first
        if validators.url(cleaned_value):
            return True

        # If no protocol, try adding http://
        if not cleaned_value.startswith(('http://', 'https://', 'ftp://')):
            test_url = f"http://{cleaned_value}"
            if validators.url(test_url):
                return True

        return False

    @staticmethod
    def _normalize_url(value: str) -> str:
        """
        Normalize URL for STIX object creation
        :input value: Raw URL string
        :return: Normalized URL string
        """
        if not value:
            return value

        # Clean up the value
        cleaned_value = value.strip()

        # Remove brackets that might be used for defanging
        cleaned_value = cleaned_value.replace('[', '').replace(']', '')

        # Add protocol if missing
        if not cleaned_value.startswith(('http://', 'https://', 'ftp://')):
            # Use http:// as default protocol
            cleaned_value = f"http://{cleaned_value}"

        return cleaned_value

    @staticmethod
    def _is_md5(value: str) -> bool:
        """
        Valid md5 regex
        :input value: Value in string
        :return: A bool
        """
        is_valid_md5 = validators.hashes.md5(value)
        if is_valid_md5:
            return True
        else:
            return False

    @staticmethod
    def _is_sha1(value: str) -> bool:
        """
        Valid sha1 regex
        :input value: Value in string
        :return: A bool
        """
        is_valid_sha1 = validators.hashes.sha1(value)
        if is_valid_sha1:
            return True
        else:
            return False

    @staticmethod
    def _is_sha256(value: str) -> bool:
        """
        Valid sha256 regex
        :input value: Value in string
        :return: A bool
        """
        is_valid_sha256 = validators.hashes.sha256(value)
        if is_valid_sha256:
            return True
        else:
            return False

    @staticmethod
    def _is_url(value: str) -> bool:
        """
        Valid URL regex including defanged URLs
        :input value: Value in string
        :return: A boolean
        """
        # Remove defanging (brackets) if present
        cleaned_value = value.replace("[", "").replace("]", "")

        # Handle defanged protocols (hxxp -> http, hxxps -> https)
        if cleaned_value.startswith('hxxp://'):
            cleaned_value = 'http://' + cleaned_value[7:]
        elif cleaned_value.startswith('hxxps://'):
            cleaned_value = 'https://' + cleaned_value[8:]

        # Add protocol if missing (common in threat feeds)
        if not cleaned_value.startswith(('http://', 'https://', 'ftp://')):
            cleaned_value = 'http://' + cleaned_value

        is_valid_url = validators.url(cleaned_value)

        if is_valid_url:
            return True
        else:
            return False

    @staticmethod
    def _normalize_url(value: str) -> str:
        """
        Normalize URL by removing defanging and adding protocol if needed
        :input value: Raw URL value in string
        :return: Normalized URL string
        """
        # Remove defanging (brackets) if present
        normalized = value.replace("[", "").replace("]", "")

        # Handle defanged protocols (hxxp -> http, hxxps -> https)
        if normalized.startswith('hxxp://'):
            normalized = 'http://' + normalized[7:]
        elif normalized.startswith('hxxps://'):
            normalized = 'https://' + normalized[8:]

        # Add protocol if missing (common in threat feeds)
        if not normalized.startswith(('http://', 'https://', 'ftp://')):
            normalized = 'http://' + normalized

        return normalized

    def _get_hash_dict(self, hash_value: str) -> dict:
        """
        Determine hash type by length and return appropriate hash dictionary
        :input hash_value: Hash value in string
        :return: Dictionary with appropriate hash type
        """
        hash_value = hash_value.strip()

        if self._is_md5(hash_value):
            return {"MD5": hash_value}
        elif self._is_sha1(hash_value):
            return {"SHA-1": hash_value}
        elif self._is_sha256(hash_value):
            return {"SHA-256": hash_value}
        else:
            self.helper.connector_logger.error(
                f"Unknown hash type for value: {hash_value}"
            )
            return {"MD5": hash_value}  # Default fallback for now

    def create_network_observable(self, value: str) -> dict:
        """
        Create network observable for CIDR notation
        Uses IPv4Address/IPv6Address with custom CIDR properties
        :input value: CIDR notation string (e.g., 192.168.1.0/24)
        :return: STIX IPv4Address or IPv6Address object with network properties
        """
        try:
            network = ipaddress.ip_network(value, strict=False)

            if network.version == 4:
                return stix2.IPv4Address(
                    value=str(network.network_address),
                    object_marking_refs=[self.tlp_marking.id],
                    custom_properties={
                        "x_opencti_created_by_ref": self.author["id"],
                        "x_opencti_labels": self.config.labels,
                        "x_opencti_description": self._create_observable_description(value, "IPv4 Network"),
                        "x_opencti_network_cidr": str(network),
                        "x_opencti_network_size": network.num_addresses,
                        "x_opencti_is_cidr": True
                    },
                )
            else:  # IPv6
                return stix2.IPv6Address(
                    value=str(network.network_address),
                    object_marking_refs=[self.tlp_marking.id],
                    custom_properties={
                        "x_opencti_created_by_ref": self.author["id"],
                        "x_opencti_labels": self.config.labels,
                        "x_opencti_description": self._create_observable_description(value, "IPv6 Network"),
                        "x_opencti_network_cidr": str(network),
                        "x_opencti_network_size": network.num_addresses,
                        "x_opencti_is_cidr": True
                    },
                )
        except Exception as e:
            self.helper.connector_logger.error(
                f"[MSI] Error creating network observable for {value}: {e}"
            )
            return None

    def create_observable(self, value: str) -> dict:
        """
        Enhanced create_observable supporting both individual IPs and CIDR notation
        :input value: Value in string
        :return: Stix object for IPV4, IPV6, Domain, or Network
        """
        # Check for CIDR notation first
        if self._is_cidr(value):
            return self.create_network_observable(value)
        elif self._is_ipv6(value) is True:
            stix_ipv6_address = stix2.IPv6Address(
                value=value,
                object_marking_refs=[self.tlp_marking.id],
                created_by_ref=self.creator_id,
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_labels": self.config.labels,
                    "x_opencti_score": self.config.score,
                    "x_opencti_description": self._create_observable_description(value, "IPv6 Address")
                },
            )
            return stix_ipv6_address
        elif self._is_ipv4(value) is True:
            stix_ipv4_address = stix2.IPv4Address(
                value=value,
                object_marking_refs=[self.tlp_marking.id],
                created_by_ref=self.creator_id,
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_labels": self.config.labels,
                    "x_opencti_score": self.config.score,
                    "x_opencti_description": self._create_observable_description(value, "IPv4 Address")
                },
            )
            return stix_ipv4_address
        elif self._is_domain(value) is True:
            stix_domain_name = stix2.DomainName(
                value=value,
                object_marking_refs=[self.tlp_marking.id],
                custom_properties={
                    "x_opencti_score": self.config.score,
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_labels": self.config.labels,
                    "x_opencti_description": self._create_observable_description(value, "Domain")
                },
            )
            return stix_domain_name
        elif self._is_email(value) is True:
            stix_email_address = stix2.EmailAddress(
                value=value,
                object_marking_refs=[self.tlp_marking.id],
                created_by_ref=self.creator_id,
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_labels": self.config.labels,
                    "x_opencti_score": self.config.score,
                    "x_opencti_description": self._create_observable_description(value, "Email Address")
                }
            )
            return stix_email_address
        elif self._is_url(value) is True:
            # Normalize the URL for STIX object creation
            normalized_url = self._normalize_url(value)
            return stix2.URL(
                value=normalized_url,
                object_marking_refs=[self.tlp_marking.id],
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_labels": self.config.labels,
                    "x_opencti_score": self.config.score,
                    "x_opencti_description": self._create_observable_description(value, "URL")
                }
            )
        elif self._is_md5(value) is True:
            return stix2.File(
          hashes={"MD5": value},
          object_marking_refs=[self.tlp_marking.id],
          created_by_ref=self.creator_id,
          custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_labels": self.config.labels,
                    "x_opencti_score": self.config.score,
                    "x_opencti_description": self._create_observable_description(value, "MD5 Hash")
                }
            )
        elif self._is_sha1(value) is True:
            return stix2.File(
                hashes={"SHA-1": value},
                object_marking_refs=[self.tlp_marking.id],
                created_by_ref=self.creator_id,
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_labels": self.config.labels,
                    "x_opencti_score": self.config.score,
                    "x_opencti_description": self._create_observable_description(value, "SHA1 Hash")
                }
            )
        elif self._is_sha256(value) is True:
            return stix2.File(
                hashes={"SHA-256": value},
                object_marking_refs=[self.tlp_marking.id],
                created_by_ref=self.creator_id,
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_labels": self.config.labels,
                    "x_opencti_score": self.config.score,
                    "x_opencti_description": self._create_observable_description(value, "SHA256 Hash")
                }
            )
        elif self._is_url(value) is True:
            normalized_url = self._normalize_url(value)
            stix_url = stix2.URL(
                value=normalized_url,
                object_marking_refs=[self.tlp_marking.id],
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_labels": self.config.labels,
                    "x_opencti_score": self.config.score,
                    "x_opencti_description": self._create_observable_description(normalized_url, "URL")
                }
            )
            return stix_url
        else:
            self.helper.connector_logger.error(
                "This observable value is not a valid IPv4 or IPv6 address, DomainName, Email, URL, or File Hash: ",
                {"value": value},
            )

    def create_entities_from_source_data(self, entities: list) -> list:
        """
        Create STIX objects from source data based on configuration
        :param entities: List of entities from source
        :return: List of STIX objects
        """
        stix_objects = []
        all_entity_objects = []  # Store all entity objects for relationship creation

        # First pass: Create all STIX objects
        for entity in entities:
            try:
                entity_objects = {}

                for entity_type in self.config.entity_types:
                    if entity_type == "indicator":
                        obj = self._create_indicator_from_entity(entity)
                    elif entity_type == "malware":
                        obj = self._create_malware_from_entity(entity)
                    elif entity_type == "infrastructure":
                        obj = self._create_infrastructure_from_entity(entity)
                    elif entity_type == "vulnerability":
                        obj = self._create_vulnerability_from_entity(entity)
                    elif entity_type == "attack-pattern":
                        obj = self._create_attack_pattern_from_entity(entity)
                    elif entity_type in ["ipv4-addr", "ipv6-addr", "domain-name", "file", "email-addr", "url"]:
                        obj = self._create_observable_from_entity(entity, entity_type)
                    else:
                        self.helper.connector_logger.warning(
                            f"[MSI] Unsupported entity type: {entity_type}"
                        )
                        continue

                    if obj:
                        entity_objects[entity_type] = obj
                        stix_objects.append(obj)

                all_entity_objects.append(entity_objects)

            except Exception as e:
                self.helper.connector_logger.error(
                    f"[MSI] Error processing entity: {e}"
                )
                continue

        # Second pass: Create relationships after all objects exist
        for entity_objects in all_entity_objects:
            try:
                for rel_config in self.config.relationships:
                    source_obj = entity_objects.get(rel_config["source"])
                    target_obj = entity_objects.get(rel_config["target"])

                    if source_obj and target_obj:
                        self.helper.connector_logger.debug(
                            f"[MSI] Creating relationship: {rel_config['type']} "
                            f"from {rel_config['source']} ({source_obj.id}) to {rel_config['target']} ({target_obj.id})"
                        )
                        relationship = self.create_relationship(
                            source_obj.id,
                            rel_config["type"],
                            target_obj.id
                        )
                        stix_objects.append(relationship)
                    else:
                        self.helper.connector_logger.warning(
                            f"[MSI] Cannot create relationship {rel_config['type']}: "
                            f"source_obj={source_obj is not None}, target_obj={target_obj is not None}"
                        )
            except Exception as e:
                self.helper.connector_logger.error(
                    f"[MSI] Error creating relationships: {e}"
                )
                continue

        return stix_objects

    def _create_indicator_from_entity(self, entity: dict) -> dict:
        """Create STIX Indicator from entity data"""
        # Extract observable value from different entity structures
        observable_value = self._extract_observable_value(entity)

        if not observable_value:
            return None

        # Debug logging for troubleshooting
        self.helper.connector_logger.debug(
            f"[MSI] Processing indicator - observable_value: '{observable_value}', "
            f"is_url: {self._is_url(observable_value)}, "
            f"is_domain: {self._is_domain(observable_value)}, "
            f"is_ipv4: {self._is_ipv4(observable_value)}"
        )

        # Determine pattern type - add CIDR support
        if self._is_cidr(observable_value):
            try:
                network = ipaddress.ip_network(observable_value, strict=False)
                if network.version == 4:
                    pattern = f"[ipv4-addr:value = '{network.network_address}']"
                else:
                    pattern = f"[ipv6-addr:value = '{network.network_address}']"
            except Exception as e:
                self.helper.connector_logger.error(
                    f"[MSI] Error creating CIDR pattern for: {observable_value} - {e}"
                )
                return None
        elif self._is_ipv4(observable_value):
            pattern = f"[ipv4-addr:value = '{observable_value}']"
        elif self._is_ipv6(observable_value):
            pattern = f"[ipv6-addr:value = '{observable_value}']"
        elif self._is_domain(observable_value):
            pattern = f"[domain-name:value = '{observable_value}']"
        elif self._is_email(observable_value):
            pattern = f"[email-addr:value = '{observable_value}']"
        elif self._is_url(observable_value):
            normalized_url = self._normalize_url(observable_value)
            pattern = f"[url:value = '{normalized_url}']"
        elif self._is_md5(observable_value):
            pattern = f"[file:hashes.MD5 = '{observable_value}']"
        elif self._is_sha1(observable_value):
            pattern = f"[file:hashes.SHA1 = '{observable_value}']"
        elif self._is_sha256(observable_value):
            pattern = f"[file:hashes.SHA256 = '{observable_value}']"
        elif self._is_url(observable_value):
            normalized_url = self._normalize_url(observable_value)
            pattern = f"[url:value = '{normalized_url}']"
        else:
            self.helper.connector_logger.error(
                f"This pattern is not a valid STIX 2.1 pattern for value: '{observable_value}'"
            )
            return None

        # Create description based on source and entity data
        description = self._create_description_for_entity(entity, "indicator")

        indicator = stix2.Indicator(
            name=observable_value,
            pattern=pattern,
            pattern_type="stix",
            labels=self.config.labels,
            description=description,
            confidence=self.config.confidence,
            object_marking_refs=[self.tlp_marking.id],
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
                "x_opencti_labels": self.config.labels,
                **self._extract_custom_properties(entity)
            }
        )


        return indicator

    def _create_infrastructure_from_entity(self, entity: dict) -> dict:
        """Create STIX Infrastructure from entity data"""
        observable_value = self._extract_observable_value(entity)

        if not observable_value:
            return None

        # Create name based on source type and entity data
        name = self._create_name_for_entity(entity, "infrastructure")
        description = self._create_description_for_entity(entity, "infrastructure")

        # Determine infrastructure types based on source
        infra_types = ["anonymization"] if self.config.external_ref_name == "Tor Project" else ["hosting-infrastructure"]

        infrastructure = stix2.Infrastructure(
            name=name,
            infrastructure_types=infra_types,
            description=description,
            object_marking_refs=[self.tlp_marking.id],
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
                "x_opencti_labels": self.config.labels,
                "x_opencti_score": self.config.score,
                **self._extract_custom_properties(entity)
            }
        )
        return infrastructure

    def _create_malware_from_entity(self, entity: dict) -> dict:
        """Create STIX Malware from entity data"""
        name = entity.get("name") or entity.get("family") or f"Unknown Malware {entity.get('id', '')}"

        malware = stix2.Malware(
            name=name,
            is_family=entity.get("is_family", True),
            malware_types=entity.get("types", ["unknown"]),
            description=self._create_description_for_entity(entity, "malware"),
            object_marking_refs=[self.tlp_marking.id],
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
                "x_opencti_labels": self.config.labels,
                "x_opencti_score": self.config.score,
                **self._extract_custom_properties(entity)
            }
        )
        return malware

    def _create_vulnerability_from_entity(self, entity: dict) -> dict:
        """Create STIX Vulnerability from entity data"""
        name = entity.get("name") or entity.get("cve_id") or f"Vulnerability {entity.get('id', '')}"

        vulnerability = stix2.Vulnerability(
            name=name,
            description=self._create_description_for_entity(entity, "vulnerability"),
            object_marking_refs=[self.tlp_marking.id],
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
                "x_opencti_labels": self.config.labels,
                "x_opencti_score": self.config.score,
                **self._extract_custom_properties(entity)
            }
        )
        return vulnerability

    def _create_attack_pattern_from_entity(self, entity: dict) -> dict:
        """Create STIX Attack Pattern from entity data"""
        name = entity.get("name") or entity.get("technique") or f"Attack Pattern {entity.get('id', '')}"

        attack_pattern = stix2.AttackPattern(
            name=name,
            description=self._create_description_for_entity(entity, "attack-pattern"),
            object_marking_refs=[self.tlp_marking.id],
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
                "x_opencti_labels": self.config.labels,
                "x_opencti_score": self.config.score,
                **self._extract_custom_properties(entity)
            }
        )
        return attack_pattern

    def _create_observable_from_entity(self, entity: dict, obs_type: str) -> dict:
        """Create STIX Observable (SCO) from entity data"""
        observable_value = self._extract_observable_value(entity)

        if not observable_value:
            return None

        if obs_type == "ipv4-addr" and self._is_ipv4(observable_value):
            return self.create_observable(observable_value)
        elif obs_type == "ipv6-addr" and self._is_ipv6(observable_value):
            return self.create_observable(observable_value)
        elif obs_type == "domain-name" and self._is_domain(observable_value):
            return self.create_observable(observable_value)
        elif obs_type == "email-addr" and self._is_email(observable_value):
            return self.create_observable(observable_value)
        elif obs_type == "url" and self._is_url(observable_value):
            return self.create_observable(observable_value)
        elif obs_type == "file":
            # Create file observable with hash - detect hash type by length
            hash_dict = self._get_hash_dict(observable_value)
            # Determine hash type for description
            if len(observable_value.strip()) == 32:
                hash_type = "MD5 Hash"
            elif len(observable_value.strip()) == 40:
                hash_type = "SHA1 Hash"
            elif len(observable_value.strip()) == 64:
                hash_type = "SHA256 Hash"
            else:
                hash_type = "File Hash"

            return stix2.File(
                hashes=hash_dict,
                object_marking_refs=[self.tlp_marking.id],
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_labels": self.config.labels,
                    "x_opencti_score": self.config.score,
                    "x_opencti_description": self._create_observable_description(observable_value, hash_type)
                }
            )
        elif obs_type == "url" and self._is_url(observable_value):
            return self.create_observable(observable_value)

        return None

    def _extract_observable_value(self, entity: dict) -> str:
        """Extract observable value from entity using various possible keys"""
        # Try common keys for observable values
        possible_keys = [
            'observable_value', 'ip', 'domain', 'hash', 'md5', 'sha1', 'sha256',
            'value', 'indicator', 'ioc', 'url', 'link'
        ]

        # For Tor-specific structure
        if 'ExitAddress' in entity and isinstance(entity['ExitAddress'], dict):
            return entity['ExitAddress'].get('ip')

        # Try direct access
        for key in possible_keys:
            if key in entity and entity[key]:
                return str(entity[key])

        # Try nested access
        for key in entity.keys():
            if isinstance(entity[key], dict):
                for nested_key in possible_keys:
                    if nested_key in entity[key]:
                        return str(entity[key][nested_key])

        return None

    def _create_name_for_entity(self, entity: dict, entity_type: str) -> str:
        """Create appropriate name for entity based on type and source"""
        if self.config.external_ref_name == "Tor Project" and entity_type == "infrastructure":
            exit_node = entity.get('ExitNode', 'Unknown')
            return f"Tor Exit Node {exit_node[:8]}"

        # Generic naming patterns
        observable_value = self._extract_observable_value(entity)
        if observable_value:
            return f"{entity_type.title()} {observable_value}"

        return f"{entity_type.title()} from {self.config.external_ref_name}"

    def _create_description_for_entity(self, entity: dict, entity_type: str) -> str:
        """Create appropriate description for entity"""
        if self.config.external_ref_name == "Tor Project" and entity_type == "indicator":
            exit_node = entity.get('ExitNode', 'Unknown')
            description = f"Tor exit node with fingerprint {exit_node}"
        elif self.config.external_ref_name == "Tor Project" and entity_type == "infrastructure":
            observable_value = self._extract_observable_value(entity)
            description = f"Tor exit node infrastructure with IP {observable_value}"
        else:
            # Generic description
            observable_value = self._extract_observable_value(entity)
            if observable_value:
                description = f"{entity_type.title()} {observable_value} from {self.config.external_ref_name}"
            else:
                description = f"{entity_type.title()} from {self.config.external_ref_name}"

        # Add attribution note if creator is configured
        creator = getattr(self.config, 'creator', None)
        if creator:
            current_date = datetime.now().strftime('%Y-%m-%d')
            attribution_note = f"Added on {current_date} by: {creator}"
            description = f"{description}\n\n{attribution_note}"

        return description

    def _extract_custom_properties(self, entity: dict) -> dict:
        """Extract custom properties from entity data"""
        custom_props = {}

        # Add source-specific custom properties
        if self.config.external_ref_name == "Tor Project":
            custom_props.update({
                "x_tor_exit_fingerprint": entity.get("ExitNode"),
                "x_tor_published": entity.get("Published"),
                "x_tor_last_status": entity.get("LastStatus"),
                "x_tor_exit_timestamp": entity.get("ExitAddress", {}).get("timestamp")
            })
        elif "CyberCrime Tracker" in self.config.external_ref_name:
            custom_props.update({
                "x_cybercrime_group": entity.get("group"),
                "x_cybercrime_category": entity.get("category"),
                "x_confidence_level": entity.get("confidence")
            })

        return {k: v for k, v in custom_props.items() if v is not None}

    def _create_observable_description(self, value: str, obs_type: str) -> str:
        """Create description for observable with attribution"""
        description = f"{obs_type.title()} {value} from {self.config.external_ref_name}"

        # Add attribution note if creator is configured
        creator = getattr(self.config, 'creator', None)
        if creator:
            current_date = datetime.now().strftime('%Y-%m-%d')
            attribution_note = f"Added on {current_date} by: {creator}"
            description = f"{description}\n\n{attribution_note}"

        return description
