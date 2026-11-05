"""A stand-in PAN-OS firewall, so approving a plan sends real XML API calls and verify reads the result back.

It isn't a device and it enforces nothing. It listens on the loopback address only while a call runs, keeps its config
in the run's folder, and `FirewallSession` refuses any other address, so this code can't change a real firewall. It
speaks the part of the API a plan needs, and a commit fails the way a real one would when a rule names something
undefined.
"""

from __future__ import annotations

import json
import re
import secrets
import threading
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import httpx

from porygon_mitigator.flow.engine import traffic_action
from porygon_mitigator.flow.models import Device, Environment, FirewallRule, ObservedTraffic
from porygon_mitigator.integrations.panos.client import first_child_tag, members
from porygon_mitigator.integrations.panos.collect import DEVICE, _rule

LOOPBACK = "127.0.0.1"
PAN_OS = "PaloAltoNGFW"
VSYS = f"{DEVICE}/vsys/entry[@name='vsys1']"
PROFILES = f"{VSYS}/profiles/vulnerability"
RULES = f"{VSYS}/rulebase/security/rules"
_DEVICE_ID = re.compile(r"[\w.-]{1,120}")
_BUILT_IN_PROFILES = frozenset({"default", "strict"})
_STEP = re.compile(r"/([\w.-]+)(?:\[@name='([^']*)'\])?")
_ERROR_BAD_XPATH = "8"
_ERROR_NOT_FOUND = "7"
_ERROR_BAD_COMMAND = "1"
_ERROR_COMMIT = "13"
TIMEOUT_SECONDS = 10.0
POLL_SECONDS = 0.01
NETWORK_FILE = "network.json"
PLAN_APPLIED_FILE = "plan-applied"


class FirewallError(RuntimeError):
    """The mock refused a call or a commit, or what it holds isn't what the plan should have left."""


def state_path(folder: Path, device: str) -> Path:
    """Where a device's config is kept. An id comes from an environment file, so it can't choose another folder."""
    if not _DEVICE_ID.fullmatch(device):
        raise FirewallError(f"device id {device[:80]!r} can't be used as a mock firewall's name")
    return folder / f"{device}.json"


def _element(tag: str, name: str | None = None, *children: ET.Element) -> ET.Element:
    element = ET.Element(tag, {"name": name} if name is not None else {})
    element.extend(children)
    return element


def _members(tag: str, values: list[str]) -> ET.Element:
    element = ET.Element(tag)
    for value in values:
        ET.SubElement(element, "member").text = value
    return element


def _rule_entry(rule: FirewallRule) -> ET.Element:
    entry = _element(
        "entry",
        rule.name,
        _members("from", rule.from_zone),
        _members("to", rule.to_zone),
        _members("source", ["any"]),
        _members("destination", rule.destination),
        _members("application", ["any"]),
        _members("service", ["any"]),
    )
    ET.SubElement(entry, "action").text = rule.action
    if rule.vulnerability_profile:
        profiles = ET.SubElement(ET.SubElement(entry, "profile-setting"), "profiles")
        profiles.append(_members("vulnerability", [rule.vulnerability_profile]))
    return entry


def _exception_entry(threat_id: str) -> ET.Element:
    entry = _element("entry", threat_id)
    ET.SubElement(ET.SubElement(entry, "action"), "reset-both")
    return entry


def config_for(device: Device) -> ET.Element:
    """The device's rules and vulnerability profiles as a PAN-OS config."""
    config = ET.Element("config")
    vsys = _walk(config, VSYS, create=True)
    assert vsys is not None
    profiles = ET.SubElement(ET.SubElement(vsys, "profiles"), "vulnerability")
    for name, threat_ids in device.vulnerability_profiles.items():
        exceptions = ET.Element("threat-exception")
        exceptions.extend(_exception_entry(item) for item in threat_ids)
        profiles.append(_element("entry", name, exceptions))
    rules = ET.SubElement(ET.SubElement(ET.SubElement(vsys, "rulebase"), "security"), "rules")
    rules.extend(_rule_entry(rule) for rule in device.rules)
    return config


def _steps(xpath: str) -> list[tuple[str, str | None]]:
    if not xpath.startswith("/config") or _STEP.sub("", xpath):
        raise _ApiError(_ERROR_BAD_XPATH, f"can't read this xpath: {xpath[:200]}")
    return [(tag, name or None) for tag, name in _STEP.findall(xpath)][1:]


def _walk(config: ET.Element, xpath: str, *, create: bool = False) -> ET.Element | None:
    node = config
    for tag, name in _steps(xpath):
        found = next(
            (child for child in node if child.tag == tag and (name is None or child.get("name") == name)),
            None,
        )
        if found is None:
            if not create:
                return None
            found = ET.SubElement(node, tag, {"name": name} if name else {})
        node = found
    return node


def _merge(parent: ET.Element, incoming: ET.Element) -> None:
    if incoming.tag == "member":
        if incoming.text not in {item.text for item in parent.findall("member")}:
            parent.append(incoming)
        return
    match = next((c for c in parent if c.tag == incoming.tag and c.get("name") == incoming.get("name")), None)
    if match is None:
        parent.append(incoming)
        return
    for child in incoming:
        _merge(match, child)


def _commit_errors(config: ET.Element) -> list[str]:
    vsys = _walk(config, VSYS)
    if vsys is None:
        return ["no vsys1"]
    profiles = {item.get("name") for item in vsys.iterfind("profiles/vulnerability/entry")} | _BUILT_IN_PROFILES
    errors = []
    for rule in vsys.iterfind("rulebase/security/rules/entry"):
        name = rule.get("name")
        errors += [
            f"rule {name} names vulnerability profile {item}, which isn't defined"
            for item in members(rule.find("profile-setting/profiles"), "vulnerability")
            if item not in profiles
        ]
    return errors


class _ApiError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _answer(status: str, *children: ET.Element, code: str | None = None) -> bytes:
    response = ET.Element("response", {"status": status, **({"code": code} if code else {})})
    response.extend(children)
    return ET.tostring(response)


def _result(*children: ET.Element) -> ET.Element:
    return _element("result", None, *children)


class MockFirewalls:
    """The API's answers, with each device's config in `folder`. A device is chosen by `target`, as through Panorama."""

    def __init__(self, folder: Path, api_key: str) -> None:
        self.folder = folder
        self.api_key = api_key
        self.calls: list[dict[str, str]] = []
        self._candidates: dict[str, ET.Element] = {}
        self._lock = threading.Lock()

    def _path(self, device: str) -> Path:
        try:
            return state_path(self.folder, device)
        except FirewallError as error:
            raise _ApiError(_ERROR_NOT_FOUND, str(error)) from error

    def _state(self, device: str) -> dict[str, Any]:
        path = self._path(device)
        if not path.exists():
            raise _ApiError(_ERROR_NOT_FOUND, f"no firewall {device}")
        state: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        return state

    def _candidate(self, device: str) -> ET.Element:
        if device not in self._candidates:
            self._candidates[device] = ET.fromstring(self._state(device)["versions"][-1])  # noqa: S314 - our own file
        return self._candidates[device]

    def respond(self, params: dict[str, str], key: str | None) -> tuple[int, bytes]:
        if not key or not secrets.compare_digest(key, self.api_key):
            return 403, _answer("error", _result(_message("Invalid credential")), code="403")
        with self._lock:
            call: dict[str, str] = {
                name: params[name] for name in ("type", "action", "xpath", "target", "cmd") if name in params
            }
            self.calls.append(call)
            try:
                return 200, self._handle(params)
            except _ApiError as error:
                call["error"] = error.message
                return 200, _answer("error", _result(_message(error.message)), code=error.code)

    def _handle(self, params: dict[str, str]) -> bytes:
        device = params.get("target", "")
        kind = params.get("type")
        if kind == "config":
            return self._config(device, params)
        if kind == "commit":
            return self._commit(device)
        if kind == "log":
            return self._log(device, params)
        if kind == "op":
            return self._op(device, params.get("cmd", ""))
        raise _ApiError(_ERROR_BAD_COMMAND, f"this mock doesn't speak API type {kind!r}")

    def _config(self, device: str, params: dict[str, str]) -> bytes:
        action, xpath = params.get("action"), params.get("xpath", "")
        if action in ("show", "get"):
            source = (
                self._candidate(device)
                if action == "get"
                else ET.fromstring(  # noqa: S314 - our own file
                    self._state(device)["versions"][-1]
                )
            )
            found = _walk(source, xpath)
            return _answer("success", _result(*([found] if found is not None else [])))
        config = self._candidate(device)
        if action == "set":
            fragment = ET.fromstring(f"<fragment>{params.get('element', '')}</fragment>")  # noqa: S314 - our own caller
            target = _walk(config, xpath, create=True)
            assert target is not None
            for child in fragment:
                _merge(target, child)
        elif action == "move":
            if params.get("where") != "top":
                raise _ApiError(_ERROR_BAD_COMMAND, "this mock only moves a rule to the top")
            rule, parent = _walk(config, xpath), _walk(config, xpath.rsplit("/entry", 1)[0])
            if rule is None or parent is None:
                raise _ApiError(_ERROR_NOT_FOUND, f"nothing to move at {xpath[:200]}")
            parent.remove(rule)
            parent.insert(0, rule)
        else:
            raise _ApiError(_ERROR_BAD_COMMAND, f"this mock doesn't speak config action {action!r}")
        return _answer("success", _result(_message("command succeeded")))

    def _log(self, device: str, params: dict[str, str]) -> bytes:
        if params.get("action") != "get":
            if params.get("log-type") != "traffic":
                raise _ApiError(_ERROR_BAD_COMMAND, f"this mock has no {params.get('log-type')} log")
            self._state(device)
            return _answer("success", _result(_text("job", "1")))
        network = self._network()
        self._state(device)
        # A change to a host or a device this mock doesn't speak to leaves no new version on any firewall here.
        changed = (self.folder / PLAN_APPLIED_FILE).exists() or any(
            len(json.loads(path.read_text(encoding="utf-8"))["versions"]) > 1
            for path in self.folder.glob("*.json")
            if path.name != NETWORK_FILE
        )
        logs = _element("logs")
        for item in network.observed_traffic:
            if not item.only_after_change or changed:
                logs.append(_log_entry(item, traffic_action(network, item)))
        job = _element("job", None, _text("status", "FIN"))
        return _answer("success", _result(job, _element("log", None, logs)))

    def _network(self) -> Environment:
        """The network as this firewall's own running config has it, so a change or drift shows in what it logs."""
        path = self.folder / NETWORK_FILE
        if not path.exists():
            raise _ApiError(_ERROR_NOT_FOUND, "this mock has no traffic to report")
        network = Environment.model_validate_json(path.read_text(encoding="utf-8"))
        for device in network.devices:
            if self._path(device.id).exists():
                running = ET.fromstring(self._state(device.id)["versions"][-1])  # noqa: S314 - our own file
                device.rules, device.vulnerability_profiles = read_device(running)
        return network

    def _commit(self, device: str) -> bytes:
        config = self._candidate(device)
        errors = _commit_errors(config)
        if errors:
            raise _ApiError(_ERROR_COMMIT, "commit failed: " + "; ".join(errors[:5]))
        state = self._state(device)
        state["versions"].append(ET.tostring(config, encoding="unicode"))
        _write_state(self._path(device), state)
        return _answer("success", _result(_text("job", str(len(state["versions"])))))

    def _op(self, device: str, command: str) -> bytes:
        loaded = re.fullmatch(r"<load><config><version>(\d+)</version></config></load>", command)
        if loaded:
            versions = self._state(device)["versions"]
            number = int(loaded.group(1))
            if not 1 <= number <= len(versions):
                raise _ApiError(_ERROR_NOT_FOUND, f"no config version {number}")
            self._candidates[device] = ET.fromstring(versions[number - 1])  # noqa: S314 - our own file
            return _answer("success", _result(_message("config loaded")))
        if command == "<show><system><info></info></system></show>":
            system = _element("system", None, _text("hostname", device), _text("model", "mock"))
            return _answer("success", _result(system))
        if command.startswith("<show><predefined>"):
            return _answer("success", _result(_element("threats")))
        raise _ApiError(_ERROR_BAD_COMMAND, f"this mock doesn't speak: {command[:200]}")


def _message(text: str) -> ET.Element:
    return _text("msg", text)


def _text(tag: str, text: str) -> ET.Element:
    element = ET.Element(tag)
    element.text = text
    return element


def _write_state(path: Path, state: dict[str, Any]) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state), encoding="utf-8")
    temporary.replace(path)


def _log_entry(item: ObservedTraffic, action: str) -> ET.Element:
    entry = _element(
        "entry",
        None,
        _text("session-name", item.name),
        _text("from", item.source_zone),
        _text("dst", item.host),
        _text("repeatcnt", str(item.sessions)),
        _text("action", action),
        _text("after-change", "yes" if item.only_after_change else "no"),
    )
    entry.append(_members("threats", item.threat_ids))
    return entry


class FirewallSession:
    """API calls to a mock on this machine. The address is checked first, so it can't reach anything else."""

    def __init__(self, url: str, api_key: str) -> None:
        host = urlsplit(url).hostname or ""
        try:
            local = ip_address(host).is_loopback
        except ValueError:
            local = False
        if not local:
            raise FirewallError(f"refusing {host or url}: changes only go to the mock firewall on this machine")
        self._url = url
        self._client = httpx.Client(headers={"X-PAN-KEY": api_key}, timeout=TIMEOUT_SECONDS, trust_env=False)

    def close(self) -> None:
        self._client.close()

    def call(self, **params: str) -> ET.Element:
        try:
            response = self._client.post(self._url, data=params)
            root = ET.fromstring(response.content)  # noqa: S314 - the answer comes from our own mock
        except (httpx.HTTPError, ET.ParseError) as error:
            raise FirewallError(f"the mock firewall didn't answer: {type(error).__name__}") from error
        if root.get("status") != "success":
            detail = " ".join(text.strip() for text in root.itertext() if text.strip())
            raise FirewallError(detail or "the mock firewall returned an error")
        return root

    def traffic(self, device: str) -> list[tuple[ObservedTraffic, str]]:
        """The firewall's traffic log, read the way a real one is: start a log job, then fetch it."""
        job = self.call(type="log", target=device, **{"log-type": "traffic"}).findtext("result/job")
        result = self.call(type="log", action="get", target=device, **{"job-id": job or ""})
        return [
            (
                ObservedTraffic(
                    name=entry.findtext("session-name", ""),
                    source_zone=entry.findtext("from", ""),
                    host=entry.findtext("dst", ""),
                    sessions=int(entry.findtext("repeatcnt", "1")),
                    threat_ids=members(entry, "threats"),
                    only_after_change=entry.findtext("after-change") == "yes",
                ),
                entry.findtext("action", ""),
            )
            for entry in result.iterfind("result/log/logs/entry")
        ]

    def running(self, device: str) -> ET.Element:
        result = self.call(type="config", action="show", xpath="/config", target=device).find("result/config")
        if result is None:
            raise FirewallError(f"the mock firewall has no config for {device}")
        return result


class _Handler(BaseHTTPRequestHandler):
    server: _Server

    def _reply(self, params: dict[str, str]) -> None:
        status, body = self.server.firewalls.respond(params, self.headers.get("X-PAN-KEY"))
        self.send_response(status)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self._reply(dict(parse_qsl(urlsplit(self.path).query)))

    def do_POST(self) -> None:
        size = int(self.headers.get("Content-Length") or 0)
        self._reply(dict(parse_qsl(self.rfile.read(size).decode("utf-8"), keep_blank_values=True)))

    def log_message(self, format: str, *args: object) -> None:
        return


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request: object, client_address: object) -> None:
        return  # The caller sees the dropped connection as FirewallError, so this needn't print a traceback too.

    def __init__(self, firewalls: MockFirewalls) -> None:
        super().__init__((LOOPBACK, 0), _Handler)
        self.firewalls = firewalls


@contextmanager
def serving(folder: Path) -> Iterator[tuple[FirewallSession, MockFirewalls]]:
    """The mock on a free loopback port, for as long as the block runs."""
    firewalls = MockFirewalls(folder, secrets.token_hex(16))
    server = _Server(firewalls)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": POLL_SECONDS}, daemon=True)
    thread.start()
    session = FirewallSession(f"http://{LOOPBACK}:{server.server_address[1]}/api/", firewalls.api_key)
    try:
        yield session, firewalls
    finally:
        session.close()
        server.shutdown()
        server.server_close()
        thread.join()


def read_device(config: ET.Element) -> tuple[list[FirewallRule], dict[str, list[str]]]:
    """A running config back in the model's terms, read with the collector's own parsing."""
    vsys = _walk(config, VSYS)
    if vsys is None:
        return [], {}
    rules = []
    for entry in vsys.iterfind("rulebase/security/rules/entry"):
        parsed = _rule(entry, {}, "security")
        rules.append(
            FirewallRule(
                name=parsed["name"],
                from_zone=parsed["from"],
                to_zone=parsed["to"],
                destination=parsed["destination"],
                action=parsed["action"],
                vulnerability_profile=parsed.get("profile_setting", {}).get("vulnerability"),
            )
        )
    profiles = {
        entry.get("name", ""): [
            item.get("name", "")
            for item in entry.iterfind("threat-exception/entry")
            if first_child_tag(item, "action") == "reset-both"
        ]
        for entry in vsys.iterfind("profiles/vulnerability/entry")
    }
    return rules, profiles


def _calls_for(before: Device, after: Device) -> list[dict[str, str]]:
    """The API calls that turn one device into the other. A plan only adds, so anything else can't be sent."""
    known_rules = {rule.name: rule for rule in before.rules}
    if set(known_rules) - {rule.name for rule in after.rules}:
        raise FirewallError(f"a plan removed a rule on {before.id}, which it never should")
    calls: list[dict[str, str]] = []

    def send(action: str, xpath: str, *elements: ET.Element, **extra: str) -> None:
        body = "".join(ET.tostring(item, encoding="unicode") for item in elements)
        calls.append({"action": action, "xpath": xpath, **({"element": body} if elements else {}), **extra})

    for name, threat_ids in after.vulnerability_profiles.items():
        already = before.vulnerability_profiles.get(name)
        if already is None:
            send("set", PROFILES, _element("entry", name))
        new = [item for item in threat_ids if item not in (already or [])]
        if new:
            send("set", f"{PROFILES}/entry[@name='{name}']/threat-exception", *map(_exception_entry, new))
    for rule in reversed(after.rules):
        if rule.name in known_rules:
            continue
        send("set", RULES, _rule_entry(rule))
        send("move", f"{RULES}/entry[@name='{rule.name}']", where="top")
    for rule in after.rules:
        old = known_rules.get(rule.name)
        if old is None or old.vulnerability_profile == rule.vulnerability_profile:
            continue
        send(
            "set",
            f"{RULES}/entry[@name='{rule.name}']/profile-setting/profiles/vulnerability",
            _text("member", rule.vulnerability_profile or ""),
        )
    return calls


def _settings_the_model_lacks(config: ET.Element) -> list[str]:
    """Rule settings the model has no field for. The flow writes one value for each, so another means a change."""
    vsys = _walk(config, VSYS)
    found = []
    for entry in [] if vsys is None else vsys.iterfind("rulebase/security/rules/entry"):
        parsed = _rule(entry, {}, "security")
        if parsed["disabled"] or parsed["negate_source"] or parsed["negate_destination"]:
            found.append(f"rule {parsed['name']} is disabled or negated")
        if parsed["source"] != ["any"] or parsed["application"] != ["any"] or parsed["service"] != ["any"]:
            found.append(f"rule {parsed['name']} has a source, application or service the model doesn't")
    return found


def _differences_in(config: ET.Element, device: Device) -> list[str]:
    try:
        rules, profiles = read_device(config)
    except ValueError as error:
        return [f"{device.id}: its config can't be read: {type(error).__name__}"]
    return [
        *(f"{device.id}: {item}" for item in _settings_the_model_lacks(config)),
        *_differences(rules, profiles, device),
    ]


def _differences(rules: list[FirewallRule], profiles: dict[str, list[str]], device: Device) -> list[str]:
    differences = []
    held = [rule.model_dump(mode="json") for rule in rules]
    model = [rule.model_dump(mode="json") for rule in device.rules]
    if held != model:
        differences.append(f"{device.id}: its rules aren't the ones in the model")
    if {name: sorted(items) for name, items in profiles.items()} != {
        name: sorted(items) for name, items in device.vulnerability_profiles.items()
    }:
        differences.append(f"{device.id}: its vulnerability profiles aren't the ones in the model")
    return differences


def start_firewalls(folder: Path, environment: Environment) -> list[str]:
    """Give every PAN-OS device in this network a mock with its current config. Returns their ids."""
    folder.mkdir(parents=True, exist_ok=True)
    (folder / NETWORK_FILE).write_text(environment.model_dump_json(), encoding="utf-8")
    devices = [device for device in environment.devices if device.fw_type == PAN_OS]
    for device in devices:
        path = state_path(folder, device.id)
        _write_state(path, {"versions": [ET.tostring(config_for(device), encoding="unicode")]})
    return [device.id for device in devices]


def read_traffic(folder: Path) -> list[tuple[ObservedTraffic, str]]:
    """The traffic log over the API. One device's log covers the whole network: the mock has one set of sessions."""
    devices = sorted(path.stem for path in folder.glob("*.json") if path.name != NETWORK_FILE)
    if not devices:
        return []
    with serving(folder) as (session, _firewalls):
        return session.traffic(devices[0])


def push_plan(folder: Path, before: Environment, after: Environment) -> dict[str, Any]:
    """Send what the plan changes on each firewall, commit, and read it back. A device with nothing to change gets no
    calls. Raises FirewallError when any of it fails, and the caller drops the folder."""
    old = {device.id: device for device in before.devices}
    changed = [device for device in after.devices if device != old[device.id]]
    sent = [device for device in changed if device.fw_type == PAN_OS]
    start_firewalls(folder, before)
    # Host changes matter to what the log shows, so the mock holds them too. Its firewalls keep their own configs.
    (folder / NETWORK_FILE).write_text(after.model_dump_json(), encoding="utf-8")
    if after != before:
        (folder / PLAN_APPLIED_FILE).touch()
    receipt: dict[str, Any] = {
        "mock": True,
        "devices": [],
        "not_sent": [f"{device.id}: the mock only speaks PAN-OS" for device in changed if device.fw_type != PAN_OS],
    }
    with serving(folder) as (session, firewalls):
        for device in sent:
            firewalls.calls.clear()
            for call in _calls_for(old[device.id], device):
                session.call(type="config", target=device.id, **call)
            job = session.call(type="commit", target=device.id, cmd="<commit></commit>").findtext("result/job")
            differences = _differences_in(session.running(device.id), device)
            if differences:
                raise FirewallError("; ".join(differences))
            receipt["devices"].append(
                {
                    "device": device.id,
                    "commit_job": job,
                    "calls": [
                        {key: call[key] for key in ("type", "action", "xpath") if key in call}
                        for call in firewalls.calls
                    ],
                }
            )
    return receipt


def undo_plan(folder: Path, receipt: dict[str, Any]) -> list[dict[str, Any]]:
    """Load each firewall's config from before the plan, commit it, and read back whether that's what it now holds."""
    undone = []
    with serving(folder) as (session, firewalls):
        for item in receipt.get("devices", []):
            device = item["device"]
            first = json.loads(state_path(folder, device).read_text(encoding="utf-8"))["versions"][0]
            session.call(type="op", target=device, cmd="<load><config><version>1</version></config></load>")
            job = session.call(type="commit", target=device, cmd="<commit></commit>").findtext("result/job")
            held = ET.tostring(session.running(device), encoding="unicode")
            undone.append({"device": device, "commit_job": job, "restored": held == first, "config": held})
        firewalls.calls.clear()
    (folder / PLAN_APPLIED_FILE).unlink(missing_ok=True)
    return undone


def firewall_differences(folder: Path, receipt: dict[str, Any], environment: Environment) -> list[str]:
    """Where what each firewall really holds, read over the API, differs from the model."""
    by_id = {device.id: device for device in environment.devices}
    differences: list[str] = []
    with serving(folder) as (session, _firewalls):
        for item in receipt.get("devices", []):
            try:
                config = session.running(item["device"])
            except FirewallError as error:
                differences.append(f"{item['device']}: {error}")
                continue
            differences += _differences_in(config, by_id[item["device"]])
    return differences
