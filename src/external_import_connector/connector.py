import sys

from pycti import OpenCTIConnectorHelper

from .client_api import ConfigurableTextClient, ConfigurableHtmlClient
from .config_loader import ConfigConnector
from .converter_to_stix import ConverterToStix


class ConnectorTemplate:
    """
    Specifications of the external import connector

    This class encapsulates the main actions, expected to be run by any external import connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector aim to fetch external data to create STIX bundle and send it in a RabbitMQ queue.
    The STIX bundle in the queue will be processed by the workers.
    This type of connector uses the basic methods of the helper.

    ---

    Attributes
        - `config (ConfigConnector())`:
            Initialize the connector with necessary configuration environment variables

        - `helper (OpenCTIConnectorHelper(config))`:
            This is the helper to use.
            ALL connectors have to instantiate the connector helper with configurations.
            Doing this will do a lot of operations behind the scene.

        - `source_processors`: Dictionary of source-specific clients and converters

    ---

    Best practices
        - `self.helper.api.work.initiate_work(...)` is used to initiate a new work
        - `self.helper.schedule_iso()` is used to encapsulate the main process in a scheduler
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message
        - `self.helper.stix2_create_bundle(stix_objects)` is used when creating a bundle
        - `self.helper.send_stix2_bundle(stix_objects_bundle)` is used to send the bundle to RabbitMQ
        - `self.helper.set_state()` is used to set state

    """

    def __init__(self, config: ConfigConnector, helper: OpenCTIConnectorHelper):
        """
        Initialize the Connector with necessary configurations
        """
        # Load configuration file and connection helper
        self.config = config
        self.helper = helper

        # Initialize multi-source processors
        self.source_processors = {}

        # TODO: ERROR CHECKING IF VALUES ARE SET
        # Initialize sources from configuration
        # if not hasattr(config, 'sources') or not config.sources:
        #     raise ValueError("No sources configured. Please configure sources in config.yml")

        if not config.client_type:
                raise ValueError(f"Source missing required field 'client_type'. Must be 'raw_text' or 'html'")
        client_type = config.client_type
        if client_type == 'html':
            client = ConfigurableHtmlClient(self.helper, config)
        elif client_type == 'raw_text':
            client = ConfigurableTextClient(self.helper, config)
        else:
            raise ValueError(f"Source has invalid client_type '{client_type}'. Must be 'raw_text' or 'html'")

        converter = ConverterToStix(self.helper, config)

        self.source_processors = {
            "client": client,
            "converter": converter,
            "config": config
        }

        self.helper.connector_logger.info(
            f"[MSI] Initialized {len(self.source_processors)} source processors: {list(self.source_processors.keys())}"
        )

    def _collect_intelligence(self) -> list:
        """
        Collect intelligence from all configured sources
        :return: List of STIX objects from all sources
        """
        return self._collect_single_source()

    def _collect_single_source(self) -> list:
        """
        Collect intelligence from a configured sources
        Only processes sources that are due to run based on their duration_period
        :return: List of STIX objects from all sources
        """
        all_stix_objects = []

        try:
            self.helper.connector_logger.info(
                f"[MSI] Starting intelligence collection"
            )

            # Get entities from source
            entities = self.source_processors["client"].get_entities()
            # print(entities)
            if not entities:
                self.helper.connector_logger.info(
                    f"[MSI] No entities retrieved"
                )

            # Convert to STIX objects using the new flexible method
            stix_objects = self.source_processors["converter"].create_entities_from_source_data(entities)

            # Check if entities were retrieved but no STIX objects created
            if entities and not stix_objects:
                self.helper.connector_logger.warning(
                    f"[MSI] Retrieved {len(entities)} entities but created 0 STIX objects. "
                    f"Check capture_regex pattern and ensure URL returns raw text (not HTML/JSON)"
                )

            # Add source metadata objects (author and TLP marking)
            if stix_objects:
                stix_objects.extend([
                    self.source_processors["converter"].author,
                    self.source_processors["converter"].tlp_marking
                ])
                self.helper.connector_logger.info(
                    f"[MSI] Added metadata objects. Total STIX objects now: {len(stix_objects)}"
                    )


            all_stix_objects.extend(stix_objects)

            self.helper.connector_logger.info(
                f"[MSI] Created {len(stix_objects)} STIX objects"
            )


        except Exception as e:
            self.helper.connector_logger.error(
                f"[MSI] Error during collection: {e}"
            )

        self.helper.connector_logger.info(
            f"[MSI] Processed..."
        )
        self.helper.connector_logger.info(
            f"[MSI] Total STIX objects from all sources: {len(all_stix_objects)}"
        )

        return all_stix_objects


    def process_message(self) -> None:
        """
        Connector main process to collect intelligence
        :return: None
        """
        self.helper.connector_logger.info(
            "[MSI] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )

        try:
            # Friendly name to be displayed on OpenCTI platform
            source_names = list(self.source_processors.keys())
            friendly_name = f"Multi-Source Intelligence Connector:{self.config.external_ref_name} ({len(source_names)} sources: {', '.join(source_names)})"

            # New work
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            self.helper.connector_logger.info(
                "[MSI] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            # Performing the collection of intelligence
            # ===========================
            # === Add your code below ===
            # ===========================
            stix_objects = self._collect_intelligence()

            if len(stix_objects):
                stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
                bundles_sent = self.helper.send_stix2_bundle(
                    stix_objects_bundle,
                    work_id=work_id,
                    cleanup_inconsistent_bundle=True,
                )

                self.helper.connector_logger.info(
                    "Sending STIX objects to OpenCTI...",
                    {"bundles_sent": {str(len(bundles_sent))}},
                )
            # ===========================
            # === Add your code above ===
            # ===========================
            message = (
                f"{self.helper.connect_name} connector successfully run"
            )

            self.helper.api.work.to_processed(work_id, message)
            self.helper.connector_logger.info(message)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[MSI] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))

    def run(self) -> None:
        """
        Run the main process encapsulated in a scheduler
        It allows you to schedule the process to run at a certain intervals
        This specific scheduler from the pycti connector helper will also check the queue size of a connector
        If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)

        The connector now uses the shortest duration_period from all enabled sources to ensure
        frequent enough checks while respecting individual source schedules.
        :return: None
        """
        self.helper.connector_logger.info('[MSI] Start processing message');
        self.process_message()
        self.helper.connector_logger.info('[MSI] Message processed');
