#!/usr/bin/env python3
# Modified version of "charms.loki_k8s.v0.loki_push_api" v0.12

import json
import logging
import os
import platform
import re
import subprocess
import tempfile
import typing
import uuid
from copy import deepcopy
from gzip import GzipFile
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from typing import List, Optional, Tuple, cast
from urllib import request
from urllib.error import HTTPError

import yaml
from charms.observability_libs.v0.juju_topology import JujuTopology
from ops.charm import (
    CharmBase,
    RelationCreatedEvent,
    RelationEvent,
    WorkloadEvent,
)
from ops.framework import EventBase, EventSource, Object, ObjectEvents
from ops.model import Container, ModelError
from ops.pebble import APIError, ChangeError, PathError, ProtocolError

logger = logging.getLogger(__name__)

RELATION_INTERFACE_NAME = "loki_push_api"
DEFAULT_RELATION_NAME = "logging"
DEFAULT_ALERT_RULES_RELATIVE_PATH = "./src/loki_alert_rules"
DEFAULT_LOG_PROXY_RELATION_NAME = "log-proxy"

PROMTAIL_BASE_URL = "https://github.com/canonical/loki-k8s-operator/releases/download"
# To update Promtail version you only need to change the PROMTAIL_VERSION and
# update all sha256 sums in PROMTAIL_BINARIES. To support a new architecture
# you only need to add a new key value pair for the architecture in PROMTAIL_BINARIES.
PROMTAIL_VERSION = "v2.5.0"
PROMTAIL_BINARIES = {
    "amd64": {
        "filename": "promtail-static-amd64",
        "zipsha": "543e333b0184e14015a42c3c9e9e66d2464aaa66eca48b29e185a6a18f67ab6d",
        "binsha": "17e2e271e65f793a9fbe81eab887b941e9d680abe82d5a0602888c50f5e0cac9",
    },
}

# Paths in `charm` container
BINARY_DIR = "/tmp"

# Paths in `workload` container
WORKLOAD_BINARY_DIR = "/opt/promtail"
WORKLOAD_CONFIG_DIR = "/etc/promtail"
WORKLOAD_CONFIG_FILE_NAME = "promtail_config.yaml"
WORKLOAD_CONFIG_PATH = "{}/{}".format(WORKLOAD_CONFIG_DIR, WORKLOAD_CONFIG_FILE_NAME)
WORKLOAD_POSITIONS_PATH = "{}/positions.yaml".format(WORKLOAD_BINARY_DIR)
WORKLOAD_SERVICE_NAME = "promtail"

HTTP_LISTEN_PORT = 9080
GRPC_LISTEN_PORT = 9095


class InvalidAlertRulePathError(Exception):
    """Raised if the alert rules folder cannot be found or is otherwise invalid."""

    def __init__(
        self,
        alert_rules_absolute_path: Path,
        message: str,
    ):
        self.alert_rules_absolute_path = alert_rules_absolute_path
        self.message = message

        super().__init__(self.message)


def _is_official_alert_rule_format(rules_dict: dict) -> bool:
    """Are alert rules in the upstream format as supported by Loki.

    Alert rules in dictionary format are in "official" form if they
    contain a "groups" key, since this implies they contain a list of
    alert rule groups.

    Args:
        rules_dict: a set of alert rules in Python dictionary format

    Returns:
        True if alert rules are in official Loki file format.
    """
    return "groups" in rules_dict


def _is_single_alert_rule_format(rules_dict: dict) -> bool:
    """Are alert rules in single rule format.

    The Loki charm library supports reading of alert rules in a
    custom format that consists of a single alert rule per file. This
    does not conform to the official Loki alert rule file format
    which requires that each alert rules file consists of a list of
    alert rule groups and each group consists of a list of alert
    rules.

    Alert rules in dictionary form are considered to be in single rule
    format if in the least it contains two keys corresponding to the
    alert rule name and alert expression.

    Returns:
        True if alert rule is in single rule file format.
    """
    # one alert rule per file
    return set(rules_dict) >= {"alert", "expr"}


class AlertRules:
    """Utility class for amalgamating Loki alert rule files and injecting juju topology.

    An `AlertRules` object supports aggregating alert rules from files and directories in both
    official and single rule file formats using the `add_path()` method. All the alert rules
    read are annotated with Juju topology labels and amalgamated into a single data structure
    in the form of a Python dictionary using the `as_dict()` method. Such a dictionary can be
    easily dumped into JSON format and exchanged over relation data. The dictionary can also
    be dumped into YAML format and written directly into an alert rules file that is read by
    Loki. Note that multiple `AlertRules` objects must not be written into the same file,
    since Loki allows only a single list of alert rule groups per alert rules file.

    The official Loki format is a YAML file conforming to the Loki documentation
    (https://grafana.com/docs/loki/latest/api/#list-rule-groups).
    The custom single rule format is a subsection of the official YAML, having a single alert
    rule, effectively "one alert per file".
    """

    # This class uses the following terminology for the various parts of a rule file:
    # - alert rules file: the entire groups[] yaml, including the "groups:" key.
    # - alert groups (plural): the list of groups[] (a list, i.e. no "groups:" key) - it is a list
    #   of dictionaries that have the "name" and "rules" keys.
    # - alert group (singular): a single dictionary that has the "name" and "rules" keys.
    # - alert rules (plural): all the alerts in a given alert group - a list of dictionaries with
    #   the "alert" and "expr" keys.
    # - alert rule (singular): a single dictionary that has the "alert" and "expr" keys.

    def __init__(self, topology: Optional[JujuTopology] = None):
        """Build and alert rule object.

        Args:
            topology: a `JujuTopology` instance that is used to annotate all alert rules.
        """
        self.topology = topology
        self.tool = CosTool(None)
        self.alert_groups = []  # type: List[dict]

    def _from_file(self, root_path: Path, file_path: Path) -> List[dict]:
        """Read a rules file from path, injecting juju topology.

        Args:
            root_path: full path to the root rules folder (used only for generating group name)
            file_path: full path to a *.rule file.

        Returns:
            A list of dictionaries representing the rules file, if file is valid (the structure is
            formed by `yaml.safe_load` of the file); an empty list otherwise.
        """
        with file_path.open() as rf:
            # Load a list of rules from file then add labels and filters
            try:
                rule_file = yaml.safe_load(rf) or {}

            except Exception as e:
                logger.error("Failed to read alert rules from %s: %s", file_path.name, e)
                return []

            if _is_official_alert_rule_format(rule_file):
                alert_groups = rule_file["groups"]
            elif _is_single_alert_rule_format(rule_file):
                # convert to list of alert groups
                # group name is made up from the file name
                alert_groups = [{"name": file_path.stem, "rules": [rule_file]}]
            else:
                # invalid/unsupported
                reason = "file is empty" if not rule_file else "unexpected file structure"
                logger.error("Invalid rules file (%s): %s", reason, file_path.name)
                return []

            # update rules with additional metadata
            for alert_group in alert_groups:
                # update group name with topology and sub-path
                alert_group["name"] = self._group_name(
                    str(root_path),
                    str(file_path),
                    alert_group["name"],
                )

                # add "juju_" topology labels
                for alert_rule in alert_group["rules"]:
                    if "labels" not in alert_rule:
                        alert_rule["labels"] = {}

                    if self.topology:
                        alert_rule["labels"].update(self.topology.label_matcher_dict)
                        # insert juju topology filters into a prometheus alert rule
                        # logql doesn't like empty matchers, so add a job matcher which hits
                        # any string as a "wildcard" which the topology labels will
                        # filter down
                        alert_rule["expr"] = self.tool.inject_label_matchers(
                            re.sub(r"%%juju_topology%%", r'job=".+"', alert_rule["expr"]),
                            self.topology.label_matcher_dict,
                        )

            return alert_groups

    def _group_name(
        self,
        root_path: typing.Union[Path, str],
        file_path: typing.Union[Path, str],
        group_name: str,
    ) -> str:
        """Generate group name from path and topology.

        The group name is made up of the relative path between the root dir_path, the file path,
        and topology identifier.

        Args:
            root_path: path to the root rules dir.
            file_path: path to rule file.
            group_name: original group name to keep as part of the new augmented group name

        Returns:
            New group name, augmented by juju topology and relative path.
        """
        file_path = Path(file_path) if not isinstance(file_path, Path) else file_path
        root_path = Path(root_path) if not isinstance(root_path, Path) else root_path
        rel_path = file_path.parent.relative_to(root_path.as_posix())

        # We should account for both absolute paths and Windows paths. Convert it to a POSIX
        # string, strip off any leading /, then join it

        path_str = ""
        if not rel_path == Path("."):
            # Get rid of leading / and optionally drive letters so they don't muck up
            # the template later, since Path.parts returns them. The 'if relpath.is_absolute ...'
            # isn't even needed since re.sub doesn't throw exceptions if it doesn't match, so it's
            # optional, but it makes it clear what we're doing.

            # Note that Path doesn't actually care whether the path is valid just to instantiate
            # the object, so we can happily strip that stuff out to make templating nicer
            rel_path = Path(
                re.sub(r"^([A-Za-z]+:)?/", "", rel_path.as_posix())
                if rel_path.is_absolute()
                else str(rel_path)
            )

            # Get rid of relative path characters in the middle which both os.path and pathlib
            # leave hanging around. We could use path.resolve(), but that would lead to very
            # long template strings when rules come from pods and/or other deeply nested charm
            # paths
            path_str = "_".join(filter(lambda x: x not in ["..", "/"], rel_path.parts))

        # Generate group name:
        #  - name, from juju topology
        #  - suffix, from the relative path of the rule file;
        group_name_parts = [self.topology.identifier] if self.topology else []
        group_name_parts.extend([path_str, group_name, "alerts"])
        # filter to remove empty strings
        return "_".join(filter(lambda x: x, group_name_parts))

    @classmethod
    def _multi_suffix_glob(
        cls, dir_path: Path, suffixes: List[str], recursive: bool = True
    ) -> list:
        """Helper function for getting all files in a directory that have a matching suffix.

        Args:
            dir_path: path to the directory to glob from.
            suffixes: list of suffixes to include in the glob (items should begin with a period).
            recursive: a flag indicating whether a glob is recursive (nested) or not.

        Returns:
            List of files in `dir_path` that have one of the suffixes specified in `suffixes`.
        """
        all_files_in_dir = dir_path.glob("**/*" if recursive else "*")
        return list(filter(lambda f: f.is_file() and f.suffix in suffixes, all_files_in_dir))

    def _from_dir(self, dir_path: Path, recursive: bool) -> List[dict]:
        """Read all rule files in a directory.

        All rules from files for the same directory are loaded into a single
        group. The generated name of this group includes juju topology.
        By default, only the top directory is scanned; for nested scanning, pass `recursive=True`.

        Args:
            dir_path: directory containing *.rule files (alert rules without groups).
            recursive: flag indicating whether to scan for rule files recursively.

        Returns:
            a list of dictionaries representing prometheus alert rule groups, each dictionary
            representing an alert group (structure determined by `yaml.safe_load`).
        """
        alert_groups = []  # type: List[dict]

        # Gather all alerts into a list of groups
        for file_path in self._multi_suffix_glob(dir_path, [".rule", ".rules"], recursive):
            alert_groups_from_file = self._from_file(dir_path, file_path)
            if alert_groups_from_file:
                logger.debug("Reading alert rule from %s", file_path)
                alert_groups.extend(alert_groups_from_file)

        return alert_groups

    def add_path(self, path: str, *, recursive: bool = False):
        """Add rules from a dir path.

        All rules from files are aggregated into a data structure representing a single rule file.
        All group names are augmented with juju topology.

        Args:
            path: either a rules file or a dir of rules files.
            recursive: whether to read files recursively or not (no impact if `path` is a file).

        Raises:
            InvalidAlertRulePathError: if the provided path is invalid.
        """
        path = Path(path)  # type: Path
        if path.is_dir():
            self.alert_groups.extend(self._from_dir(path, recursive))
        elif path.is_file():
            self.alert_groups.extend(self._from_file(path.parent, path))
        else:
            logger.debug("The alerts file does not exist: %s", path)

    def as_dict(self) -> dict:
        """Return standard alert rules file in dict representation.

        Returns:
            a dictionary containing a single list of alert rule groups.
            The list of alert rule groups is provided as value of the
            "groups" dictionary key.
        """
        return {"groups": self.alert_groups} if self.alert_groups else {}


def _resolve_dir_against_charm_path(charm: CharmBase, *path_elements: str) -> str:
    """Resolve the provided path items against the directory of the main file.

    Look up the directory of the `main.py` file being executed. This is normally
    going to be the charm.py file of the charm including this library. Then, resolve
    the provided path elements and, if the result path exists and is a directory,
    return its absolute path; otherwise, raise en exception.

    Raises:
        InvalidAlertRulePathError, if the path does not exist or is not a directory.
    """
    charm_dir = Path(str(charm.charm_dir))
    if not charm_dir.exists() or not charm_dir.is_dir():
        # Operator Framework does not currently expose a robust
        # way to determine the top level charm source directory
        # that is consistent across deployed charms and unit tests
        # Hence for unit tests the current working directory is used
        # TODO: updated this logic when the following ticket is resolved
        # https://github.com/canonical/operator/issues/643
        charm_dir = Path(os.getcwd())

    alerts_dir_path = charm_dir.absolute().joinpath(*path_elements)

    if not alerts_dir_path.exists():
        raise InvalidAlertRulePathError(alerts_dir_path, "directory does not exist")
    if not alerts_dir_path.is_dir():
        raise InvalidAlertRulePathError(alerts_dir_path, "is not a directory")

    return str(alerts_dir_path)


class ConsumerBase(Object):
    """Consumer's base class."""

    def __init__(
        self,
        charm: CharmBase,
        relation_name: str = DEFAULT_RELATION_NAME,
        alert_rules_path: str = DEFAULT_ALERT_RULES_RELATIVE_PATH,
        recursive: bool = False,
    ):
        super().__init__(charm, relation_name)
        self._charm = charm
        self._relation_name = relation_name
        self.topology = JujuTopology.from_charm(charm)

        try:
            alert_rules_path = _resolve_dir_against_charm_path(charm, alert_rules_path)
        except InvalidAlertRulePathError as e:
            logger.debug(
                "Invalid Loki alert rules folder at %s: %s",
                e.alert_rules_absolute_path,
                e.message,
            )
        self._alert_rules_path = alert_rules_path

        self._recursive = recursive

    def _handle_alert_rules(self, relation):
        if not self._charm.unit.is_leader():
            return

        alert_rules = AlertRules(self.topology)
        alert_rules.add_path(self._alert_rules_path, recursive=self._recursive)
        alert_rules_as_dict = alert_rules.as_dict()

        relation.data[self._charm.app]["metadata"] = json.dumps(self.topology.as_dict())
        relation.data[self._charm.app]["alert_rules"] = json.dumps(
            alert_rules_as_dict,
            sort_keys=True,  # sort, to prevent unnecessary relation_changed events
        )

    @property
    def loki_endpoints(self) -> List[dict]:
        """Fetch Loki Push API endpoints sent from LokiPushApiProvider through relation data.

        Returns:
            A list of dictionaries with Loki Push API endpoints, for instance:
            [
                {"url": "http://loki1:3100/loki/api/v1/push"},
                {"url": "http://loki2:3100/loki/api/v1/push"},
            ]
        """
        endpoints = []  # type: list

        for relation in self._charm.model.relations[self._relation_name]:
            for unit in relation.units:
                if unit.app == self._charm.app:
                    # This is a peer unit
                    continue

                endpoint = relation.data[unit].get("endpoint")
                if endpoint:
                    deserialized_endpoint = json.loads(endpoint)
                    endpoints.append(deserialized_endpoint)

        return endpoints


class ContainerNotFoundError(Exception):
    """Raised if the specified container does not exist."""

    def __init__(self):
        msg = "The specified container does not exist."
        self.message = msg

        super().__init__(self.message)


class MultipleContainersFoundError(Exception):
    """Raised if no container name is passed but multiple containers are present."""

    def __init__(self):
        msg = (
            "No 'container_name' parameter has been specified; since this Charmed Operator"
            " is has multiple containers, container_name must be specified for the container"
            " to get logs from."
        )
        self.message = msg

        super().__init__(self.message)


class PromtailDigestError(EventBase):
    """Event emitted when there is an error with Promtail initialization."""

    def __init__(self, handle, message):
        super().__init__(handle)
        self.message = message

    def snapshot(self):
        """Save message information."""
        return {"message": self.message}

    def restore(self, snapshot):
        """Restore message information."""
        self.message = snapshot["message"]


class LogProxyEndpointDeparted(EventBase):
    """Event emitted when a Log Proxy has departed."""


class LogProxyEndpointJoined(EventBase):
    """Event emitted when a Log Proxy joins."""


class LogProxyEvents(ObjectEvents):
    """Event descriptor for events raised by `LogProxyConsumer`."""

    promtail_digest_error = EventSource(PromtailDigestError)
    log_proxy_endpoint_departed = EventSource(LogProxyEndpointDeparted)
    log_proxy_endpoint_joined = EventSource(LogProxyEndpointJoined)


class LogProxyConsumer(ConsumerBase):
    """LogProxyConsumer class.

    The `LogProxyConsumer` object provides a method for attaching `promtail` to
    a workload in order to generate structured logging data from applications
    which traditionally log to syslog or do not have native Loki integration.
    The `LogProxyConsumer` can be instantiated as follows:

        self._log_proxy_consumer = LogProxyConsumer(self, log_files=["/var/log/messages"])

    Args:
        charm: a `CharmBase` object that manages this `LokiPushApiConsumer` object.
            Typically, this is `self` in the instantiating class.
        log_files: a list of log files to monitor with Promtail.
        relation_name: the string name of the relation interface to look up.
            If `charm` has exactly one relation with this interface, the relation's
            name is returned. If none or multiple relations with the provided interface
            are found, this method will raise either an exception of type
            NoRelationWithInterfaceFoundError or MultipleRelationsWithInterfaceFoundError,
            respectively.
        enable_syslog: Whether to enable syslog integration.
        syslog_port: The port syslog is attached to.
        alert_rules_path: an optional path for the location of alert rules
            files. Defaults to "./src/loki_alert_rules",
            resolved from the directory hosting the charm entry file.
            The alert rules are automatically updated on charm upgrade.
        recursive: Whether to scan for rule files recursively.
        container_name: An optional container name to inject the payload into.
        promtail_resource_name: An optional promtail resource name from metadata
            if it has been modified and attached

    Raises:
        RelationNotFoundError: If there is no relation in the charm's metadata.yaml
            with the same name as provided via `relation_name` argument.
        RelationInterfaceMismatchError: The relation with the same name as provided
            via `relation_name` argument does not have the `loki_push_api` relation
            interface.
        RelationRoleMismatchError: If the relation with the same name as provided
            via `relation_name` argument does not have the `RelationRole.provides`
            role.
    """

    on = LogProxyEvents()

    def __init__(
        self,
        charm,
        log_files: list = None,
        relation_name: str = DEFAULT_LOG_PROXY_RELATION_NAME,
        enable_syslog: bool = False,
        syslog_port: int = 1514,
        alert_rules_path: str = DEFAULT_ALERT_RULES_RELATIVE_PATH,
        recursive: bool = False,
        container_name: str = "",
        container = None, # overrides container_name
        promtail_resource_name: Optional[str] = None,
    ):
        super().__init__(charm, relation_name, alert_rules_path, recursive)
        self._charm = charm
        self._relation_name = relation_name

        # Get container
        if container:
            self._container = container
            self._container_name = container.name
        else:
            self._container = self._get_container(container_name)
            self._container_name = self._get_container_name(container_name)

        self._log_files = log_files or []
        self._syslog_port = syslog_port
        self._is_syslog = enable_syslog
        self.topology = JujuTopology.from_charm(charm)
        self._promtail_resource_name = promtail_resource_name or "promtail-bin"

        # architechure used for promtail binary
        arch = platform.processor()
        self._arch = "amd64" if arch == "x86_64" else arch

        events = self._charm.on[relation_name]
        self.framework.observe(events.relation_created, self._on_relation_created)
        self.framework.observe(events.relation_changed, self._on_relation_changed)
        self.framework.observe(events.relation_departed, self._on_relation_departed)
        # turn the container name to a valid Python identifier
        snake_case_container_name = self._container_name.replace("-", "_")
        self.framework.observe(
            getattr(self._charm.on, "{}_pebble_ready".format(snake_case_container_name)),
            self._on_pebble_ready,
        )

    def _on_pebble_ready(self, _: WorkloadEvent):
        """Event handler for `pebble_ready`."""
        if self.model.relations[self._relation_name]:
            self._setup_promtail()

    def _on_relation_created(self, _: RelationCreatedEvent) -> None:
        """Event handler for `relation_created`."""
        if not self._container.can_connect():
            return
        self._setup_promtail()

    def _on_relation_changed(self, event: RelationEvent) -> None:
        """Event handler for `relation_changed`.

        Args:
            event: The event object `RelationChangedEvent`.
        """
        self._handle_alert_rules(event.relation)

        if self._charm.unit.is_leader():
            ev = json.loads(event.relation.data[event.app].get("event", "{}"))

            if ev:
                valid = bool(ev.get("valid", True))
                errors = ev.get("errors", "")

                if valid and not errors:
                    self.on.alert_rule_status_changed.emit(valid=valid)
                else:
                    self.on.alert_rule_status_changed.emit(valid=valid, errors=errors)

        if not self._container.can_connect():
            return
        if self.model.relations[self._relation_name]:
            if "promtail" not in self._container.get_plan().services:
                self._setup_promtail()
                return

            new_config = self._promtail_config
            if new_config != self._current_config:
                self._container.push(
                    WORKLOAD_CONFIG_PATH, yaml.safe_dump(new_config), make_dirs=True
                )

            # Loki may send endpoints late. Don't necessarily start, there may be
            # no clients
            if new_config["clients"]:
                self._container.restart(WORKLOAD_SERVICE_NAME)
                self.on.log_proxy_endpoint_joined.emit()
            else:
                self.on.promtail_digest_error.emit("No promtail client endpoints available!")

    def _on_relation_departed(self, _: RelationEvent) -> None:
        """Event handler for `relation_departed`.

        Args:
            event: The event object `RelationDepartedEvent`.
        """
        if not self._container.can_connect():
            return
        if not self._charm.model.relations[self._relation_name]:
            self._container.stop(WORKLOAD_SERVICE_NAME)
            return

        new_config = self._promtail_config
        if new_config != self._current_config:
            self._container.push(WORKLOAD_CONFIG_PATH, yaml.safe_dump(new_config), make_dirs=True)

        if new_config["clients"]:
            self._container.restart(WORKLOAD_SERVICE_NAME)
        else:
            self._container.stop(WORKLOAD_SERVICE_NAME)
        self.on.log_proxy_endpoint_departed.emit()

    def _get_container(self, container_name: str = "") -> Container:
        """Gets a single container by name or using the only container running in the Pod.

        If there is more than one container in the Pod a `PromtailDigestError` is emitted.

        Args:
            container_name: The container name.

        Returns:
            A `ops.model.Container` object representing the container.

        Emits:
            PromtailDigestError, if there was a problem obtaining a container.
        """
        try:
            container_name = self._get_container_name(container_name)
            return self._charm.unit.get_container(container_name)
        except (MultipleContainersFoundError, ContainerNotFoundError, ModelError) as e:
            msg = str(e)
            logger.warning(msg)
            self.on.promtail_digest_error.emit(msg)

    def _get_container_name(self, container_name: str = None) -> str:
        """Helper function for getting/validating a container name.

        Args:
            container_name: The container name to be validated (optional).

        Returns:
            container_name: The same container_name that was passed (if it exists) or the only
            container name that is present (if no container_name was passed).

        Raises:
            ContainerNotFoundError, if container_name does not exist.
            MultipleContainersFoundError, if container_name was not provided but multiple
            containers are present.
        """
        containers = dict(self._charm.model.unit.containers)
        if len(containers) == 0:
            e = ContainerNotFoundError
            e.message = f'Containers are: {self._charm.model.unit.containers}'
            raise e

        if not container_name:
            # container_name was not provided - will get it ourselves, if it is the only one
            if len(containers) > 1:
                raise MultipleContainersFoundError

            # Get the first key in the containers' dict.
            # Need to "cast", otherwise:
            # error: Incompatible return value type (got "Optional[str]", expected "str")
            container_name = cast(str, next(iter(containers.keys())))

        elif container_name not in containers:
            raise ContainerNotFoundError

        return container_name

    def _add_pebble_layer(self, workload_binary_path: str) -> None:
        """Adds Pebble layer that manages Promtail service in Workload container.

        Args:
            workload_binary_path: string providing path to promtail binary in workload container.
        """
        pebble_layer = {
            "summary": "promtail layer",
            "description": "pebble config layer for promtail",
            "services": {
                WORKLOAD_SERVICE_NAME: {
                    "override": "replace",
                    "summary": WORKLOAD_SERVICE_NAME,
                    "command": "{} {}".format(workload_binary_path, self._cli_args),
                    "startup": "disabled",
                }
            },
        }
        self._container.add_layer(self._container_name, pebble_layer, combine=True)

    def _create_directories(self) -> None:
        """Creates the directories for Promtail binary and config file."""
        self._container.make_dir(path=WORKLOAD_BINARY_DIR, make_parents=True)
        self._container.make_dir(path=WORKLOAD_CONFIG_DIR, make_parents=True)

    def _obtain_promtail(self, promtail_info: dict) -> None:
        """Obtain promtail binary from an attached resource or download it.

        Args:
            promtail_info: dictionary containing information about promtail binary
               that must be used. The dictionary must have three keys
               - "filename": filename of promtail binary
               - "zipsha": sha256 sum of zip file of promtail binary
               - "binsha": sha256 sum of unpacked promtail binary
        """
        workload_binary_path = os.path.join(WORKLOAD_BINARY_DIR, promtail_info["filename"])
        if self._promtail_attached_as_resource:
            self._push_promtail_if_attached(workload_binary_path)
            return

        if self._promtail_must_be_downloaded(promtail_info):
            self._download_and_push_promtail_to_workload(promtail_info)
        else:
            binary_path = os.path.join(BINARY_DIR, promtail_info["filename"])
            self._push_binary_to_workload(binary_path, workload_binary_path)

    def _push_binary_to_workload(self, binary_path: str, workload_binary_path: str) -> None:
        """Push promtail binary into workload container.

        Args:
            binary_path: path in charm container from which promtail binary is read.
            workload_binary_path: path in workload container to which promtail binary is pushed.
        """
        with open(binary_path, "rb") as f:
            self._container.push(workload_binary_path, f, permissions=0o755, make_dirs=True)
            logger.debug("The promtail binary file has been pushed to the workload container.")

    @property
    def _promtail_attached_as_resource(self) -> bool:
        """Checks whether Promtail binary is attached to the charm or not.

        Returns:
            a boolean representing whether Promtail binary is attached as a resource or not.
        """
        try:
            self._charm.model.resources.fetch(self._promtail_resource_name)
            return True
        except ModelError:
            return False
        except NameError as e:
            if "invalid resource name" in str(e):
                return False
            else:
                raise

    def _push_promtail_if_attached(self, workload_binary_path: str) -> bool:
        """Checks whether Promtail binary is attached to the charm or not.

        Args:
            workload_binary_path: string specifying expected path of promtail
                in workload container

        Returns:
            a boolean representing whether Promtail binary is attached or not.
        """
        logger.info("Promtail binary file has been obtained from an attached resource.")
        resource_path = self._charm.model.resources.fetch(self._promtail_resource_name)
        self._push_binary_to_workload(resource_path, workload_binary_path)
        return True

    def _promtail_must_be_downloaded(self, promtail_info: dict) -> bool:
        """Checks whether promtail binary must be downloaded or not.

        Args:
            promtail_info: dictionary containing information about promtail binary
               that must be used. The dictionary must have three keys
               - "filename": filename of promtail binary
               - "zipsha": sha256 sum of zip file of promtail binary
               - "binsha": sha256 sum of unpacked promtail binary

        Returns:
            a boolean representing whether Promtail binary must be downloaded or not.
        """
        binary_path = os.path.join(BINARY_DIR, promtail_info["filename"])
        if not self._is_promtail_binary_in_charm(binary_path):
            return True

        if not self._sha256sums_matches(binary_path, promtail_info["binsha"]):
            return True

        logger.debug("Promtail binary file is already in the the charm container.")
        return False

    def _sha256sums_matches(self, file_path: str, sha256sum: str) -> bool:
        """Checks whether a file's sha256sum matches or not with an specific sha256sum.

        Args:
            file_path: A string representing the files' patch.
            sha256sum: The sha256sum against which we want to verify.

        Returns:
            a boolean representing whether a file's sha256sum matches or not with
            an specific sha256sum.
        """
        try:
            with open(file_path, "rb") as f:
                file_bytes = f.read()
                result = sha256(file_bytes).hexdigest()

                if result != sha256sum:
                    msg = "File sha256sum mismatch, expected:'{}' but got '{}'".format(
                        sha256sum, result
                    )
                    logger.debug(msg)
                    return False

                return True
        except (APIError, FileNotFoundError):
            msg = "File: '{}' could not be opened".format(file_path)
            logger.error(msg)
            return False

    def _is_promtail_binary_in_charm(self, binary_path: str) -> bool:
        """Check if Promtail binary is already stored in charm container.

        Args:
            binary_path: string path of promtail binary to check

        Returns:
            a boolean representing whether Promtail is present or not.
        """
        return True if Path(binary_path).is_file() else False

    def _download_and_push_promtail_to_workload(self, promtail_info: dict) -> None:
        """Downloads a Promtail zip file and pushes the binary to the workload.

        Args:
            promtail_info: dictionary containing information about promtail binary
               that must be used. The dictionary must have three keys
               - "filename": filename of promtail binary
               - "zipsha": sha256 sum of zip file of promtail binary
               - "binsha": sha256 sum of unpacked promtail binary
        """
        with request.urlopen(promtail_info["url"]) as r:
            file_bytes = r.read()
            file_path = os.path.join(BINARY_DIR, promtail_info["filename"] + ".gz")
            with open(file_path, "wb") as f:
                f.write(file_bytes)
                logger.info(
                    "Promtail binary zip file has been downloaded and stored in: %s",
                    file_path,
                )

            decompressed_file = GzipFile(fileobj=BytesIO(file_bytes))
            binary_path = os.path.join(BINARY_DIR, promtail_info["filename"])
            with open(binary_path, "wb") as outfile:
                outfile.write(decompressed_file.read())
                logger.debug("Promtail binary file has been downloaded.")

        workload_binary_path = os.path.join(WORKLOAD_BINARY_DIR, promtail_info["filename"])
        self._push_binary_to_workload(binary_path, workload_binary_path)

    @property
    def _cli_args(self) -> str:
        """Return the cli arguments to pass to promtail.

        Returns:
            The arguments as a string
        """
        return "-config.file={}".format(WORKLOAD_CONFIG_PATH)

    @property
    def _current_config(self) -> dict:
        """Property that returns the current Promtail configuration.

        Returns:
            A dict containing Promtail configuration.
        """
        if not self._container.can_connect():
            logger.debug("Could not connect to promtail container!")
            return {}
        try:
            raw_current = self._container.pull(WORKLOAD_CONFIG_PATH).read()
            return yaml.safe_load(raw_current)
        except (ProtocolError, PathError) as e:
            logger.warning(
                "Could not check the current promtail configuration due to "
                "a failure in retrieving the file: %s",
                e,
            )
            return {}

    @property
    def _promtail_config(self) -> dict:
        """Generates the config file for Promtail."""
        config = {"clients": self._clients_list()}
        config.update(self._server_config())
        config.update(self._positions())
        config.update(self._scrape_configs())
        return config

    def _clients_list(self) -> list:
        """Generates a list of clients for use in the promtail config.

        Returns:
            A list of endpoints
        """
        return self.loki_endpoints

    def _server_config(self) -> dict:
        """Generates the server section of the Promtail config file.

        Returns:
            A dict representing the `server` section.
        """
        return {
            "server": {
                "http_listen_port": HTTP_LISTEN_PORT,
                "grpc_listen_port": GRPC_LISTEN_PORT,
            }
        }

    def _positions(self) -> dict:
        """Generates the positions section of the Promtail config file.

        Returns:
            A dict representing the `positions` section.
        """
        return {"positions": {"filename": WORKLOAD_POSITIONS_PATH}}

    def _scrape_configs(self) -> dict:
        """Generates the scrape_configs section of the Promtail config file.

        Returns:
            A dict representing the `scrape_configs` section.
        """
        job_name = "juju_{}".format(self.topology.identifier)

        # The new JujuTopology doesn't include unit, but LogProxyConsumer should have it
        common_labels = {
            "juju_{}".format(k): v
            for k, v in self.topology.as_dict(remapped_keys={"charm_name": "charm"}).items()
        }
        scrape_configs = []

        # Files config
        labels = common_labels.copy()
        labels.update(
            {
                "job": job_name,
                "__path__": "",
            }
        )
        config = {"targets": ["localhost"], "labels": labels}
        scrape_config = {
            "job_name": "system",
            "static_configs": self._generate_static_configs(config),
        }
        scrape_configs.append(scrape_config)

        # Syslog config
        if self._is_syslog:
            relabel_mappings = [
                "severity",
                "facility",
                "hostname",
                "app_name",
                "proc_id",
                "msg_id",
            ]
            syslog_labels = common_labels.copy()
            syslog_labels.update({"job": "{}_syslog".format(job_name)})
            syslog_config = {
                "job_name": "syslog",
                "syslog": {
                    "listen_address": "127.0.0.1:{}".format(self._syslog_port),
                    "label_structured_data": True,
                    "labels": syslog_labels,
                },
                "relabel_configs": [
                    {"source_labels": ["__syslog_message_{}".format(val)], "target_label": val}
                    for val in relabel_mappings
                ]
                + [{"action": "labelmap", "regex": "__syslog_message_sd_(.+)"}],
            }
            scrape_configs.append(syslog_config)  # type: ignore

        return {"scrape_configs": scrape_configs}

    def _generate_static_configs(self, config: dict) -> list:
        """Generates static_configs section.

        Returns:
            - a list of dictionaries representing static_configs section
        """
        static_configs = []

        for _file in self._log_files:
            conf = deepcopy(config)
            conf["labels"]["__path__"] = _file
            static_configs.append(conf)

        return static_configs

    def _setup_promtail(self) -> None:
        # Use the first
        relations = self._charm.model.relations[self._relation_name]
        if len(relations) > 1:
            logger.debug(
                "Multiple log_proxy relations. Getting Promtail from application {}".format(
                    relations[0].app.name
                )
            )
        relation = relations[0]
        promtail_binaries = json.loads(
            relation.data[relation.app].get("promtail_binary_zip_url", "{}")
        )
        if not promtail_binaries:
            return

        if not self._is_promtail_installed(promtail_binaries[self._arch]):
            try:
                self._obtain_promtail(promtail_binaries[self._arch])
            except HTTPError as e:
                msg = "Promtail binary couldn't be downloaded - {}".format(str(e))
                logger.warning(msg)
                self.on.promtail_digest_error.emit(msg)
                return

        workload_binary_path = os.path.join(
            WORKLOAD_BINARY_DIR, promtail_binaries[self._arch]["filename"]
        )

        self._create_directories()
        self._container.push(
            WORKLOAD_CONFIG_PATH, yaml.safe_dump(self._promtail_config), make_dirs=True
        )

        self._add_pebble_layer(workload_binary_path)

        if self._current_config.get("clients"):
            try:
                self._container.restart(WORKLOAD_SERVICE_NAME)
            except ChangeError as e:
                self.on.promtail_digest_error.emit(str(e))
            else:
                self.on.log_proxy_endpoint_joined.emit()
        else:
            self.on.promtail_digest_error.emit("No promtail client endpoints available!")

    def _is_promtail_installed(self, promtail_info: dict) -> bool:
        """Determine if promtail has already been installed to the container.

        Args:
            promtail_info: dictionary containing information about promtail binary
               that must be used. The dictionary must at least contain a key
               "filename" giving the name of promtail binary
        """
        workload_binary_path = "{}/{}".format(WORKLOAD_BINARY_DIR, promtail_info["filename"])
        try:
            self._container.list_files(workload_binary_path)
        except (APIError, FileNotFoundError):
            return False
        return True

    @property
    def syslog_port(self) -> str:
        """Gets the port on which promtail is listening for syslog.

        Returns:
            A str representing the port
        """
        return str(self._syslog_port)

    @property
    def rsyslog_config(self) -> str:
        """Generates a config line for use with rsyslog.

        Returns:
            The rsyslog config line as a string
        """
        return 'action(type="omfwd" protocol="tcp" target="127.0.0.1" port="{}" Template="RSYSLOG_SyslogProtocol23Format" TCP_Framing="octet-counted")'.format(
            self._syslog_port
        )


class CosTool:
    """Uses cos-tool to inject label matchers into alert rule expressions and validate rules."""

    _path = None
    _disabled = False

    def __init__(self, charm):
        self._charm = charm

    @property
    def path(self):
        """Lazy lookup of the path of cos-tool."""
        if self._disabled:
            return None
        if not self._path:
            self._path = self._get_tool_path()
            if not self._path:
                logger.debug("Skipping injection of juju topology as label matchers")
                self._disabled = True
        return self._path

    def apply_label_matchers(self, rules) -> dict:
        """Will apply label matchers to the expression of all alerts in all supplied groups."""
        if not self.path:
            return rules
        for group in rules["groups"]:
            rules_in_group = group.get("rules", [])
            for rule in rules_in_group:
                topology = {}
                # if the user for some reason has provided juju_unit, we'll need to honor it
                # in most cases, however, this will be empty
                for label in [
                    "juju_model",
                    "juju_model_uuid",
                    "juju_application",
                    "juju_charm",
                    "juju_unit",
                ]:
                    if label in rule["labels"]:
                        topology[label] = rule["labels"][label]

                rule["expr"] = self.inject_label_matchers(rule["expr"], topology)
        return rules

    def validate_alert_rules(self, rules: dict) -> Tuple[bool, str]:
        """Will validate correctness of alert rules, returning a boolean and any errors."""
        if not self.path:
            logger.debug("`cos-tool` unavailable. Not validating alert correctness.")
            return True, ""

        with tempfile.TemporaryDirectory() as tmpdir:
            rule_path = Path(tmpdir + "/validate_rule.yaml")

            # Smash "our" rules format into what upstream actually uses, which is more like:
            #
            # groups:
            #   - name: foo
            #     rules:
            #       - alert: SomeAlert
            #         expr: up
            #       - alert: OtherAlert
            #         expr: up
            transformed_rules = {"groups": []}  # type: ignore
            for rule in rules["groups"]:
                transformed = {"name": str(uuid.uuid4()), "rules": [rule]}
                transformed_rules["groups"].append(transformed)

            rule_path.write_text(yaml.dump(transformed_rules))

            args = [str(self.path), "--format", "logql", "validate", str(rule_path)]
            # noinspection PyBroadException
            try:
                self._exec(args)
                return True, ""
            except subprocess.CalledProcessError as e:
                logger.debug("Validating the rules failed: %s", e.output)
                return False, ", ".join([line for line in e.output if "error validating" in line])

    def inject_label_matchers(self, expression, topology) -> str:
        """Add label matchers to an expression."""
        if not topology:
            return expression
        if not self.path:
            logger.debug("`cos-tool` unavailable. Leaving expression unchanged: %s", expression)
            return expression
        args = [str(self.path), "--format", "logql", "transform"]
        args.extend(
            ["--label-matcher={}={}".format(key, value) for key, value in topology.items()]
        )

        args.extend(["{}".format(expression)])
        # noinspection PyBroadException
        try:
            return self._exec(args)
        except subprocess.CalledProcessError as e:
            logger.debug('Applying the expression failed: "%s", falling back to the original', e)
            print('Applying the expression failed: "{}", falling back to the original'.format(e))
            return expression

    def _get_tool_path(self) -> Optional[Path]:
        arch = platform.processor()
        arch = "amd64" if arch == "x86_64" else arch
        res = "cos-tool-{}".format(arch)
        try:
            path = Path(res).resolve()
            path.chmod(0o777)
            return path
        except NotImplementedError:
            logger.debug("System lacks support for chmod")
        except FileNotFoundError:
            logger.debug('Could not locate cos-tool at: "{}"'.format(res))
        return None

    def _exec(self, cmd) -> str:
        result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE)
        output = result.stdout.decode("utf-8").strip()
        return output
