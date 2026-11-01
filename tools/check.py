#!/usr/bin/env python3
"""Behaviour checks for the jira-build-info atom.

Nothing here trusts the atom. A fake Jira app receives the request, verifies the JWT the way the Jira app does
(HS256 over the shared secret, iss/aud, a five minute expiry) and only then looks at the event body; this script then
re-reads the atom's own inputs and recomputes, from the documented rules, what the payload should have said --
pipeline id = Java String.hashCode of the project name, state from the Jenkins result, issue keys from the branch
names with the plugin's regex, passed = total - failed - skipped -- and compares that with what the server recorded.

    python3 tools/check.py all --jar dist/jira-build-info/jira-build-info.jar
    python3 tools/check.py run build-basic --jar ...
"""
import argparse
import base64
import hashlib
import hmac
import http.server
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

SECRET = "sh4red-s3cret"
STATES = ["unknown", "pending", "in_progress", "cancelled", "failed", "rolled_back", "successful"]
ENV_TYPES = ["development", "testing", "staging", "production", "unmapped"]
ISSUE_KEY_RE = re.compile(r"(?:(?<=[\s\W])|^)([A-Z][A-Z0-9_]{1,255}-[0-9]{1,100})(?:(?=[\s\W])|$)")
JAVA_MASK = 0xFFFFFFFF


# ------------------------------------------------------------------ independent recomputation

def java_hash(text):
    """java.lang.String.hashCode: h = 31*h + c, in signed 32 bit."""
    h = 0
    for ch in text:
        h = (31 * h + ord(ch)) & JAVA_MASK
    return h - 0x100000000 if h >= 0x80000000 else h


def expected_state(status):
    return {
        "": "in_progress",
        "SUCCESS": "successful",
        "FAILURE": "failed",
        "ABORTED": "cancelled",
        None: "in_progress",
    }.get(status, "unknown")


def expected_keys(*texts):
    found = []
    for text in texts:
        for match in ISSUE_KEY_RE.finditer(text or ""):
            if match.group(1) not in found:
                found.append(match.group(1))
    return sorted(found)


def b64url_decode(part):
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


class Server(http.server.BaseHTTPRequestHandler):
    """Records every request and answers according to `mode`; a bad JWT is refused with 401, like the app."""

    requests = []
    mode = "accept"
    secret = SECRET
    problems = []

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        record = {"path": self.path, "method": "POST",
                  "content_type": self.headers.get("Content-Type"), "raw": raw}
        try:
            header_b64, claims_b64, sig_b64 = raw.split(".")
            header = json.loads(b64url_decode(header_b64))
            claims = json.loads(b64url_decode(claims_b64))
            expected_sig = hmac.new(self.secret.encode(), f"{header_b64}.{claims_b64}".encode(), hashlib.sha256).digest()
            if not hmac.compare_digest(expected_sig, b64url_decode(sig_b64)):
                record["error"] = "signature"
            elif header.get("alg") != "HS256":
                record["error"] = "alg " + str(header.get("alg"))
            elif claims.get("iss") != "jenkins-plugin" or claims.get("aud") != "jenkins-forge-app":
                record["error"] = "claims " + json.dumps({k: claims.get(k) for k in ("iss", "aud")})
            elif claims.get("exp", 0) - claims.get("iat", 0) != 300:
                record["error"] = "expiry %s" % (claims.get("exp", 0) - claims.get("iat", 0))
            else:
                body = json.loads(claims["request_body_json"])
                record.update({"header": header, "claims": claims, "body": body})
                record["error"] = validate_event(body)
        except Exception as exc:  # noqa: BLE001 - a malformed request is a finding, not a crash
            record["error"] = "unparseable: %s" % exc

        type(self).requests.append(record)
        if record["error"]:
            self.answer(401, {"errorMessages": [record["error"]]})
            return
        body = record["body"]
        if self.mode == "reject":
            self.answer(200, {"acceptedBuilds": [], "rejectedBuilds": [{"errors": ["state not allowed"]}], "unknownIssueKeys": []}
                        if body["eventType"] == "build"
                        else {"acceptedDeployments": [], "rejectedDeployments": [{"errors": ["nope"]}], "unknownAssociations": []})
        elif self.mode == "unknown":
            self.answer(200, {"acceptedBuilds": [], "rejectedBuilds": [], "unknownIssueKeys": ["ZZZ-1"]}
                        if body["eventType"] == "build"
                        else {"acceptedDeployments": [], "rejectedDeployments": [], "unknownAssociations": [{"associationType": "issueKeys", "values": ["ZZZ-1"]}]})
        elif self.mode == "empty":
            self.answer(200, {"acceptedBuilds": [], "rejectedBuilds": [], "unknownIssueKeys": []}
                        if body["eventType"] == "build"
                        else {"acceptedDeployments": [], "rejectedDeployments": [], "unknownAssociations": []})
        elif self.mode == "bad-json":
            self.answer(200, "not json at all")
        elif self.mode == "http-400":
            self.answer(400, {"errorMessages": ["the app says no"]})
        else:
            builds = body["payload"].get("builds") or body["payload"].get("deployments")
            key = "acceptedBuilds" if body["eventType"] == "build" else "acceptedDeployments"
            entry = {"id": 4242, "pipelineId": body["pipelineId"], "buildNumber": builds[0].get("buildNumber") or builds[0].get("deploymentSequenceNumber")}
            self.answer(201, {key: [entry], "rejectedBuilds" if body["eventType"] == "build" else "rejectedDeployments": [],
                              "unknownIssueKeys" if body["eventType"] == "build" else "unknownAssociations": []})

    def answer(self, status, payload):
        data = payload if isinstance(payload, str) else json.dumps(payload)
        data = data.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def validate_event(body):
    """The Jira app's own contract: refuse anything the app would refuse, before the atom's behaviour is scored."""
    if body.get("requestType") != "event":
        return "requestType " + str(body.get("requestType"))
    kind = body.get("eventType")
    if kind not in ("build", "deployment"):
        return "eventType " + str(kind)
    for field in ("pipelineId", "pipelineName", "status", "lastUpdated", "payload"):
        if field not in body:
            return "missing " + field
    if body["status"] not in STATES:
        return "status " + str(body["status"])
    payload = body["payload"]
    if payload.get("properties", {}).get("source") != "jenkins":
        return "properties.source"
    if payload.get("providerMetadata", {}).get("product") != "jenkins":
        return "providerMetadata.product"
    items = payload.get("builds" if kind == "build" else "deployments")
    if not isinstance(items, list) or len(items) != 1:
        return "wrong number of %ss: %s" % (kind, items)
    item = items[0]
    if not str(item.get("pipelineId") or item.get("pipeline", {}).get("id")):
        return "pipeline id missing"
    if kind == "build":
        if item.get("schemaVersion") != "1.0":
            return "schemaVersion " + str(item.get("schemaVersion"))
        if not isinstance(item.get("buildNumber"), int):
            return "buildNumber " + str(item.get("buildNumber"))
        if item.get("state") != body["status"]:
            return "build state differs from the envelope"
        keys = item.get("issueKeys") or []
        if any(not isinstance(k, str) or not re.match(r"^[A-Z][A-Z0-9_]{1,255}-[0-9]{1,100}$", k) for k in keys):
            return "issueKeys " + json.dumps(keys)
        info = item.get("testInfo")
        if info is not None:
            if info["numberPassed"] != max(0, info["totalNumber"] - info["numberFailed"] - info["numberSkipped"]):
                return "testInfo passed does not add up: " + json.dumps(info)
    else:
        env = item.get("environment") or {}
        if not env.get("id") or not env.get("displayName") or env.get("type") not in ENV_TYPES:
            return "environment " + json.dumps(env)
        if not isinstance(item.get("deploymentSequenceNumber"), int):
            return "deploymentSequenceNumber " + str(item.get("deploymentSequenceNumber"))
        for assoc in item.get("associations") or []:
            if assoc.get("associationType") not in ("issueKeys", "serviceIdOrKeys") or not assoc.get("values"):
                return "association " + json.dumps(assoc)
        if item.get("pipeline", {}).get("id") != body["pipelineId"]:
            return "pipeline id differs from the envelope"
    return None


def start_server(mode="accept"):
    Server.requests = []
    Server.mode = mode
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), Server)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, port


# ------------------------------------------------------------------ running the atom

def run_atom(jar, params, secrets=None):
    jar = os.path.abspath(jar)
    directory = tempfile.mkdtemp(prefix="jibi-")
    json.dump(params, open(os.path.join(directory, "input.json"), "w"))
    json.dump(secrets if secrets is not None else {"secret": SECRET},
              open(os.path.join(directory, ".secrets.json"), "w"))
    env = dict(os.environ)
    env.update({"atom_data_dir": directory, "atom_data_input": "input.json",
                "atom_data_output": "output.json", "atom_workspace": directory})
    proc = subprocess.run([os.path.join(os.environ.get("JAVA_HOME", ""), "bin", "java") if os.environ.get("JAVA_HOME") else "java",
                           "-cp", jar, "com.jenkinschina.atom.sdk.AtomRunner"],
                          cwd=directory, env=env, capture_output=True, text=True, timeout=120)
    if not os.path.exists(os.path.join(directory, "output.json")):
        raise AssertionError("the atom wrote no output.json: %s\n%s" % (proc.returncode, proc.stderr[-2000:]))
    out = json.load(open(os.path.join(directory, "output.json")))
    return out, proc, directory


def data(out, key):
    return (out.get("data", {}).get(key) or {}).get("value", "")


CASES = {}


def case(fn):
    CASES[fn.__name__] = fn
    return fn


def base(port, **extra):
    doc = {"action": "build", "webhookUrl": "http://127.0.0.1:%d/jenkins-forge-app" % port,
           "projectName": "acme/service-api", "buildNumber": "42",
           "buildUrl": "http://jenkins.example.com/job/acme/job/service-api/42/",
           "label": "#42", "BUILD_STATUS": "SUCCESS"}
    doc.update(extra)
    return doc


def check_build_payload(port, params, out):
    """Everything here is recomputed from `params`, not read from the atom's output."""
    assert out["status"] == "success", out
    assert len(Server.requests) == 1, "expected one request, got %d" % len(Server.requests)
    request = Server.requests[0]
    assert request["error"] is None, request["error"]
    assert request["content_type"] == "application/jwt", request["content_type"]
    body = request["body"]
    project = params["projectName"]
    keys = [k.strip() for k in (params.get("issueKeys") or "").replace(",", " ").split() if k.strip()]
    if not keys:
        keys = expected_keys(params.get("branch"), params.get("changeBranch"), params.get("commitMessages"))
    expected_state_value = params.get("state") or expected_state(params.get("BUILD_STATUS"))
    assert body["pipelineId"] == str(java_hash(project)), (body["pipelineId"], java_hash(project))
    assert body["pipelineName"] == project, body["pipelineName"]
    assert body["status"] == expected_state_value, (body["status"], expected_state_value)
    build = body["payload"]["builds"][0]
    assert build["pipelineId"] == str(java_hash(project))
    assert build["buildNumber"] == int(params["buildNumber"]), build["buildNumber"]
    assert build["state"] == expected_state_value, build["state"]
    assert build["displayName"] == project, build["displayName"]
    assert build["label"] == params.get("label") or project
    assert build.get("issueKeys", []) == sorted(set(keys)), (build.get("issueKeys"), keys)
    assert abs(int(build["updateSequenceNumber"]) - time.time()) < 300, build["updateSequenceNumber"]
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$", build["lastUpdated"]), build["lastUpdated"]
    assert data(out, "pipelineId") == str(java_hash(project))
    return build


@case
def build_basic(jar):
    httpd, port = start_server()
    try:
        params = base(port, branch="feature/ABC-123-new-endpoint")
        out, _, _ = run_atom(jar, params)
        build = check_build_payload(port, params, out)
        assert build["issueKeys"] == ["ABC-123"], build["issueKeys"]
        assert build["url"] == params["buildUrl"]
        assert data(out, "accepted") == "1", out
        assert "testInfo" not in build, build
    finally:
        httpd.shutdown()


@case
def build_status_mapping(jar):
    httpd, port = start_server()
    try:
        seen = {}
        for status, expected in (("SUCCESS", "successful"), ("FAILURE", "failed"), ("ABORTED", "cancelled"),
                                 ("UNSTABLE", "unknown"), ("", "in_progress")):
            params = base(port, branch="ABC-9", BUILD_STATUS=status)
            out, _, _ = run_atom(jar, params)
            assert out["status"] == "success", (status, out)
            assert Server.requests[-1]["body"]["status"] == expected, (status, Server.requests[-1]["body"]["status"])
            assert data(out, "state") == expected
            seen[status] = expected
        assert len(Server.requests) == 5, len(Server.requests)
    finally:
        httpd.shutdown()


@case
def build_explicit_keys(jar):
    httpd, port = start_server()
    try:
        params = base(port, issueKeys="ABC-2, ABC-1  ABC-2", branch="feature/ABC-9-ignored")
        out, _, _ = run_atom(jar, params)
        build = check_build_payload(port, params, out)
        assert build["issueKeys"] == ["ABC-1", "ABC-2"], build["issueKeys"]
    finally:
        httpd.shutdown()


@case
def build_test_info(jar):
    httpd, port = start_server()
    try:
        params = base(port, issueKeys="ABC-1", testsTotal="10", testsFailed="2", testsSkipped="1")
        out, _, _ = run_atom(jar, params)
        info = check_build_payload(port, params, out)["testInfo"]
        assert info == {"totalNumber": 10, "numberPassed": 7, "numberFailed": 2, "numberSkipped": 1}, info
    finally:
        httpd.shutdown()


@case
def build_lowercase_branch_is_skipped(jar):
    """The plugin's regex needs an upper-case project key; a lower-case branch associates nothing, so nothing is sent."""
    httpd, port = start_server()
    try:
        params = base(port, branch="feature/abc-123")
        out, _, _ = run_atom(jar, params)
        assert out["status"] == "success", out
        assert data(out, "skipped") == "true", out
        assert data(out, "pipelineId") == str(java_hash(params["projectName"])), out
        assert Server.requests == [], "a skipped run must not touch the network"
    finally:
        httpd.shutdown()


@case
def build_bad_key_is_refused_locally(jar):
    httpd, port = start_server()
    try:
        out, _, _ = run_atom(jar, base(port, issueKeys="abc-1"))
        assert out["status"] == "error" and out["errorCode"] == 40006, out
        assert "abc-1" in out["message"], out["message"]
        assert Server.requests == [], "a refused key must not reach the network"
    finally:
        httpd.shutdown()


@case
def build_state_override_and_validation(jar):
    httpd, port = start_server()
    try:
        params = base(port, issueKeys="ABC-1", BUILD_STATUS="SUCCESS", state="rolled_back")
        out, _, _ = run_atom(jar, params)
        check_build_payload(port, params, out)
        out, _, _ = run_atom(jar, base(port, issueKeys="ABC-1", state="done"))
        assert out["status"] == "error" and out["errorCode"] == 40005, out
        assert "rolled_back" in out["message"], out["message"]
        assert len(Server.requests) == 1, len(Server.requests)
    finally:
        httpd.shutdown()


@case
def inputs_are_required(jar):
    httpd, port = start_server()
    try:
        out, _, _ = run_atom(jar, {"action": "build", "projectName": "acme", "buildNumber": "1"}, {})
        assert out["status"] == "error" and out["errorCode"] == 40002, out
        out, _, _ = run_atom(jar, base(port, issueKeys="ABC-1", projectName=""), {"secret": SECRET})
        assert out["status"] == "error" and out["errorCode"] == 40004, out
        out, _, _ = run_atom(jar, base(port, issueKeys="ABC-1"), {})
        assert out["status"] == "error" and out["errorCode"] == 40003, out
        out, _, _ = run_atom(jar, base(port, issueKeys="ABC-1", buildNumber="x"))
        assert out["status"] == "error" and out["errorCode"] == 40004, out
        out, _, _ = run_atom(jar, base(port, issueKeys="ABC-1", action="issue"))
        assert out["status"] == "error" and out["errorCode"] == 40001, out
        assert Server.requests == [], Server.requests
    finally:
        httpd.shutdown()


@case
def variables_are_expanded(jar):
    httpd, port = start_server()
    try:
        params = base(port, projectName="${JOB_NAME}", buildNumber="${BUILD_NUMBER}", issueKeys="ABC-1")
        params["JOB_NAME"] = "team/nightly"
        params["BUILD_NUMBER"] = "77"
        out, _, _ = run_atom(jar, params)
        body = Server.requests[-1]["body"]
        assert body["pipelineId"] == str(java_hash("team/nightly")), body["pipelineId"]
        assert body["payload"]["builds"][0]["buildNumber"] == 77
        assert out["status"] == "success", out
    finally:
        httpd.shutdown()


@case
def deployment_basic(jar):
    httpd, port = start_server()
    try:
        params = base(port, action="deployment", environmentId="env-1", environmentName="Staging",
                      environmentType="staging", branch="release/ABC-7")
        out, _, _ = run_atom(jar, params)
        assert out["status"] == "success", out
        body = Server.requests[-1]["body"]
        assert body["eventType"] == "deployment"
        assert body["pipelineId"] == str(java_hash("acme/service-api"))
        deployment = body["payload"]["deployments"][0]
        assert deployment["deploymentSequenceNumber"] == 42
        assert deployment["environment"] == {"id": "env-1", "displayName": "Staging", "type": "staging"}
        assert deployment["associations"] == [{"associationType": "issueKeys", "values": ["ABC-7"]}], deployment["associations"]
        assert deployment["pipeline"]["url"].endswith("/job/acme/job/service-api/"), deployment["pipeline"]["url"]
        assert "commands" not in deployment
        assert data(out, "accepted") == "1"
    finally:
        httpd.shutdown()


@case
def deployment_gating_and_services(jar):
    httpd, port = start_server()
    try:
        params = base(port, action="deployment", environmentId="env-1", environmentName="Prod",
                      environmentType="production", serviceIds="svc-b,svc-a", issueKeys="ABC-1",
                      enableGating="true", state="in_progress")
        out, _, _ = run_atom(jar, params)
        assert out["status"] == "success", out
        deployment = Server.requests[-1]["body"]["payload"]["deployments"][0]
        assert deployment["commands"] == [{"command": "initiate_deployment_gating"}], deployment["commands"]
        assert deployment["associations"] == [
            {"associationType": "issueKeys", "values": ["ABC-1"]},
            {"associationType": "serviceIdOrKeys", "values": ["svc-a", "svc-b"]},
        ], deployment["associations"]
        assert deployment["state"] == "in_progress"
    finally:
        httpd.shutdown()


@case
def deployment_environment_is_validated(jar):
    httpd, port = start_server()
    try:
        out, _, _ = run_atom(jar, base(port, action="deployment", environmentId="env-1", issueKeys="ABC-1"))
        assert out["status"] == "error" and out["errorCode"] == 40007, out
        assert "environmentName" in out["message"], out["message"]
        out, _, _ = run_atom(jar, base(port, action="deployment", environmentId="env-1", environmentName="Prod",
                                       environmentType="prod", issueKeys="ABC-1"))
        assert out["status"] == "error" and out["errorCode"] == 40007, out
        assert "unmapped" in out["message"], out["message"]
        assert Server.requests == [], Server.requests
    finally:
        httpd.shutdown()


@case
def deployment_without_anything_to_associate_is_skipped(jar):
    httpd, port = start_server()
    try:
        params = base(port, action="deployment", environmentId="env-1", environmentName="Prod", branch="")
        out, _, _ = run_atom(jar, params)
        assert out["status"] == "success" and data(out, "skipped") == "true", out
        assert Server.requests == [], Server.requests
    finally:
        httpd.shutdown()


@case
def jwt_is_refused_by_the_app_when_the_secret_is_wrong(jar):
    httpd, port = start_server()
    try:
        out, _, _ = run_atom(jar, base(port, issueKeys="ABC-1"), {"secret": "not-the-secret"})
        assert out["status"] == "error" and out["errorCode"] == 40009, out
        assert "401" in out["message"], out["message"]
        assert Server.requests[0]["error"] == "signature", Server.requests[0]
    finally:
        httpd.shutdown()


@case
def app_errors_are_reported(jar):
    for mode, code in (("reject", 40013), ("unknown", 40014), ("empty", 40012), ("bad-json", 40011),
                       ("http-400", 40009)):
        httpd, port = start_server(mode)
        try:
            out, _, _ = run_atom(jar, base(port, issueKeys="ABC-1"))
            assert out["status"] == "error" and out["errorCode"] == code, (mode, out)
        finally:
            httpd.shutdown()
    httpd, port = start_server("http-400")
    try:
        out, _, _ = run_atom(jar, base(port, issueKeys="ABC-1"))
        assert "the app says no" in out["message"], out["message"]
    finally:
        httpd.shutdown()


@case
def unreachable_app_is_a_third_party_error(jar):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    out, _, _ = run_atom(jar, base(port, issueKeys="ABC-1"))
    assert out["status"] == "error" and out["errorCode"] == 40010, out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["all", "run", "list"])
    parser.add_argument("name", nargs="?")
    parser.add_argument("--jar", required=False)
    args = parser.parse_args()
    if args.mode == "list":
        for name in CASES:
            print(name)
        return 0
    jar = args.jar or os.path.join("dist", "jira-build-info", "jira-build-info.jar")
    names = list(CASES) if args.mode == "all" else [args.name]
    failures = 0
    for name in names:
        try:
            CASES[name](jar)
            print("ok    %s" % name)
        except AssertionError as exc:
            failures += 1
            print("FAIL  %s: %s" % (name, exc))
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print("ERROR %s: %s: %s" % (name, type(exc).__name__, exc))
    print("%d/%d cases passed" % (len(names) - failures, len(names)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
