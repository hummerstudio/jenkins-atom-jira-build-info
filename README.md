# jira-build-info

Sends this build, or this deployment, to Jira Software Cloud — the step half of the
[atlassian-jira-software-cloud](https://plugins.jenkins.io/atlassian-jira-software-cloud/) plugin
(`jiraSendBuildInfo` / `jiraSendDeploymentInfo`).

## What the plugin actually does

Unpacked 2.0.15 (`WEB-INF/lib/atlassian-jira-software-cloud.jar`, 165 classes). The steps do not call the REST builds
API themselves: they POST to the **Jenkins app webhook** that the Jira site registers when the app is connected, and the
body travels inside a signed JWT (`JenkinsAppApi#wrapInJwt`):

- `Content-Type: application/jwt`, method `POST`, URL is the site's `webhookUrl`;
- HS256 over the shared secret, claims `iss=jenkins-plugin`, `aud=jenkins-forge-app`, `iat`, `exp = iat + 300`;
- the event body is the string value of `request_body_json`;
- the envelope is `JenkinsAppEventRequest`: `requestType=event`, `eventType=build|deployment`, `pipelineId`,
  `pipelineName`, `status`, `lastUpdated`, `payload`;
- `pipelineId` is `String.valueOf(runWrapper.getFullProjectName().hashCode())` — a Java `hashCode`, which is why this
  atom implements that hash instead of inventing an id;
- state comes from `JenkinsToJiraStatus`: no result yet → `in_progress`, SUCCESS → `successful`, FAILURE → `failed`,
  ABORTED → `cancelled`, anything else (UNSTABLE, NOT_BUILT) → `unknown`; an explicit `state` parameter wins;
- the answer lists `acceptedBuilds` / `rejectedBuilds` / `unknownIssueKeys` (or the deployment equivalents), and that
  list is the only confirmation Jira gives — the plugin's response handling ranks them the same way this atom does;
- with nothing to associate to (`issueKeys` empty and, for deployments, no service ids) the plugin sends nothing and
  reports *skipped*; so does this atom.

The deployment payload is `JiraDeploymentInfo`: `deploymentSequenceNumber`, associations (`issueKeys` and/or
`serviceIdOrKeys`), `environment{id,displayName,type}`, `pipeline{id,displayName,url}`, `commands` with
`initiate_deployment_gating` when gating is on. `environmentType` falls back to `unmapped` (the plugin's JENKINS-59862
fix) and is validated against development/testing/staging/production/unmapped.

## Differences worth knowing

- **Issue keys are checked before the request.** The plugin only extracts keys with a regex; a typo sent explicitly comes
  back much later as an "unknown issue key". Here a malformed key fails locally with `40006` and names the key.
- **No nulls in the payload.** The plugin's ObjectMapper writes nulls (`description`, `references`, `testInfo`); Jira
  ignores them. They are omitted here, so a payload diff is readable.
- **Issue keys are sorted** (the plugin emits a `HashSet`, so its order is whatever the hash table gives).
- **`skipped` is an output**, not a log line: a step that associated nothing says so.
- **Not ported:** `jiraCheckGatingStatus` (it polls a Jira endpoint in a loop until the state changes — that is a block
  step, and the atom contract is one process invocation), the freestyle post-build steps, the plugin's global site
  configuration (which site/secret to use arrives as inputs here), and the Jira app *connection* flow (`ping`,
  plugin-config upload), which belongs to the app, not to a build step.

## Inputs

`action` (build | deployment), `webhookUrl`, `secret` (password), `projectName` (default `${JOB_NAME}`), `buildNumber`
(default `${BUILD_NUMBER}`), `buildUrl` (default `${BUILD_URL}`), `label` (default `${BUILD_DISPLAY_NAME}`), `state`,
`issueKeys`, `branch` (default `${BRANCH_NAME}`), `changeBranch` (default `${CHANGE_BRANCH}`), `commitMessages`,
`description`, `testsTotal`/`testsFailed`/`testsSkipped`, and for deployments `environmentId`, `environmentName`,
`environmentType`, `serviceIds`, `enableGating`.

`${VAR}` in an input is taken from the job's parameters or the environment, like a Jenkinsfile would.

## Error codes

| code | meaning |
|---|---|
| 40001 | `action` is not build/deployment |
| 40002 | `webhookUrl` missing or not http(s) |
| 40003 | the app's shared secret is missing |
| 40004 | `projectName` missing, or `buildNumber` not a number |
| 40005 | `state` is not one of the seven Jira states |
| 40006 | an issue key is malformed, or there are more than 100 |
| 40007 | deployment environment invalid (missing id/name, unknown type) |
| 40009 | the app answered a non-2xx |
| 40010 | the app is unreachable |
| 40011 | the app answered something that is not JSON |
| 40012 | the app accepted nothing and rejected nothing |
| 40013 | Jira rejected the build/deployment |
| 40014 | Jira does not know the issue keys / service ids |

## Verification

`mvn verify` runs `src/test/java/atom/JiraBuildInfoIT.java`, which starts a fake Jira app (`FakeJiraApp`) that verifies
the JWT the way the app does (HS256 over the secret, iss/aud, a five-minute expiry) and validates the event against the
app's contract before scoring anything. The test then recomputes, from the atom's **own inputs**, what the payload
should say —
Java `hashCode` of the project name, state from `BUILD_STATUS`, issue keys from the branch names with the plugin's
regex, `passed = total - failed - skipped` — and compares that with what the server recorded. 16 cases: the four
Jenkins results plus "no result", explicit/sorted keys, test info, a lower-case branch that must be skipped without a
request, a malformed key that must never reach the network, `${VAR}` expansion, both deployment shapes, environment and
state validation, a wrong secret (the app refuses with 401), reject/unknown/empty/non-JSON/400 answers, an unreachable
app. `tools/mutations.py` plants nine bugs (UNSTABLE mapping, pipeline id, JWT expiry, content type, skipped tests,
unchecked keys, key ordering, environment validation, posting when nothing to associate) and all nine are caught.

Not verified against a real Jira Cloud site: a Jenkins app webhook URL only exists after the app is installed on a Jira
site, and this machine has none. The protocol is implemented from the plugin's source and the app's documented
JWT/envelope contract, and the fake app enforces exactly that contract.
