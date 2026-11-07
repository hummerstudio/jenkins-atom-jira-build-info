package atom;

import static atom.FakeJiraApp.list;
import static atom.FakeJiraApp.map;
import static atom.FakeJiraApp.number;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.jenkinschina.atom.sdk.testing.Atom;
import com.jenkinschina.atom.sdk.testing.AtomResult;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The jira-build-info atom against a fake Jira app that verifies the JWT the way the real app does.
 *
 * <p>Every check the old {@code tools/check.py} made is here: the payload is recomputed from the inputs (pipeline id =
 * {@link String#hashCode()}, state from the Jenkins result, issue keys from the plugin's regex, passed = total -
 * failed - skipped) and compared with what the app actually received, never with the atom's own report.
 */
class JiraBuildInfoIT {

    private Atom atom;

    @BeforeEach
    void setUp() throws Exception {
        atom = Atom.of();
    }

    @Test
    @DisplayName("a build event: hash id, mapped state, issue key from the branch, no testInfo when none was given")
    void buildBasic() throws Exception {
        try (FakeJiraApp app = FakeJiraApp.start("accept")) {
            Map<String, String> params = base(app);
            params.put("branch", "feature/ABC-123-new-endpoint");

            AtomResult run = run(params, FakeJiraApp.SECRET);
            Map<String, Object> body = payload(run, app);
            Map<String, Object> build = build(body);

            assertEquals(List.of("ABC-123"), strings(build.get("issueKeys")));
            assertEquals(params.get("buildUrl"), build.get("url"));
            assertEquals("1", run.field("accepted"), run.toString());
            assertFalse(build.containsKey("testInfo"), "no test counts were given: " + build);
        }
    }

    @Test
    @DisplayName("BUILD_STATUS maps to the Jira states the plugin uses: successful/failed/cancelled/unknown/in_progress")
    void statusMapping() throws Exception {
        try (FakeJiraApp app = FakeJiraApp.start("accept")) {
            Map<String, String> expected = new LinkedHashMap<>();
            expected.put("SUCCESS", "successful");
            expected.put("FAILURE", "failed");
            expected.put("ABORTED", "cancelled");
            expected.put("UNSTABLE", "unknown");
            expected.put("", "in_progress");

            for (Map.Entry<String, String> entry : expected.entrySet()) {
                Map<String, String> params = base(app);
                params.put("branch", "ABC-9");
                params.put("BUILD_STATUS", entry.getKey());

                AtomResult run = run(params, FakeJiraApp.SECRET);
                run.assertOk();
                List<FakeJiraApp.Request> requests = app.requests();
                assertEquals(entry.getValue(), requests.get(requests.size() - 1).body().get("status"),
                        entry.getKey() + " must map to " + entry.getValue());
                assertEquals(entry.getValue(), run.field("state"));
            }
            assertEquals(5, app.requests().size());
        }
    }

    @Test
    @DisplayName("explicit issueKeys are parsed, de-duplicated and sorted, and the branch is then ignored")
    void explicitKeys() throws Exception {
        try (FakeJiraApp app = FakeJiraApp.start("accept")) {
            Map<String, String> params = base(app);
            params.put("issueKeys", "ABC-2, ABC-1  ABC-2");
            params.put("branch", "feature/ABC-9-ignored");

            AtomResult run = run(params, FakeJiraApp.SECRET);
            assertEquals(List.of("ABC-1", "ABC-2"), strings(build(payload(run, app)).get("issueKeys")));
        }
    }

    @Test
    @DisplayName("test counts produce testInfo with passed = total - failed - skipped")
    void testInfo() throws Exception {
        try (FakeJiraApp app = FakeJiraApp.start("accept")) {
            Map<String, String> params = base(app);
            params.put("issueKeys", "ABC-1");
            params.put("testsTotal", "10");
            params.put("testsFailed", "2");
            params.put("testsSkipped", "1");

            AtomResult run = run(params, FakeJiraApp.SECRET);
            Map<String, Object> info = map(build(payload(run, app)).get("testInfo"));

            assertEquals(10, number(info.get("totalNumber")));
            assertEquals(7, number(info.get("numberPassed")));
            assertEquals(2, number(info.get("numberFailed")));
            assertEquals(1, number(info.get("numberSkipped")));
        }
    }

    @Test
    @DisplayName("a lower-case branch associates nothing, so nothing is sent at all")
    void lowerCaseBranchIsSkipped() throws Exception {
        try (FakeJiraApp app = FakeJiraApp.start("accept")) {
            Map<String, String> params = base(app);
            params.put("branch", "feature/abc-123");

            AtomResult run = run(params, FakeJiraApp.SECRET);

            run.assertOk();
            assertEquals("true", run.field("skipped"), run.toString());
            assertEquals(String.valueOf("acme/service-api".hashCode()), run.field("pipelineId"));
            assertTrue(app.requests().isEmpty(), "a skipped run must not touch the network");
        }
    }

    @Test
    @DisplayName("an issue key that is not upper case is refused locally, naming it")
    void badKeyIsRefusedLocally() throws Exception {
        try (FakeJiraApp app = FakeJiraApp.start("accept")) {
            Map<String, String> params = base(app);
            params.put("issueKeys", "abc-1");

            AtomResult run = run(params, FakeJiraApp.SECRET);

            run.assertRefused();
            assertEquals("40006", run.field("errorCode"), run.toString());
            assertTrue(run.field("message").contains("abc-1"), run.field("message"));
            assertTrue(app.requests().isEmpty(), "a refused key must not reach the network");
        }
    }

    @Test
    @DisplayName("an explicit state wins, and a state the app does not know is refused before sending")
    void stateOverrideAndValidation() throws Exception {
        try (FakeJiraApp app = FakeJiraApp.start("accept")) {
            Map<String, String> params = base(app);
            params.put("issueKeys", "ABC-1");
            params.put("BUILD_STATUS", "SUCCESS");
            params.put("state", "rolled_back");

            AtomResult accepted = run(params, FakeJiraApp.SECRET);
            assertEquals("rolled_back",
                    payload(accepted, app, "acme/service-api", "rolled_back").get("status"));

            Map<String, String> bad = base(app);
            bad.put("issueKeys", "ABC-1");
            bad.put("state", "done");

            AtomResult refused = run(bad, FakeJiraApp.SECRET);
            refused.assertRefused();
            assertEquals("40005", refused.field("errorCode"), refused.toString());
            assertTrue(refused.field("message").contains("rolled_back"), refused.field("message"));
            assertEquals(1, app.requests().size(), "the refused run must not have sent anything");
        }
    }

    @Test
    @DisplayName("the required inputs are checked in order: webhook, secret, project, build number, action")
    void inputsAreRequired() throws Exception {
        try (FakeJiraApp app = FakeJiraApp.start("accept")) {
            Map<String, String> noWebhook = new LinkedHashMap<>();
            noWebhook.put("action", "build");
            noWebhook.put("projectName", "acme");
            noWebhook.put("buildNumber", "1");
            assertEquals("40002", run(noWebhook, "").field("errorCode"));

            Map<String, String> noProject = base(app);
            noProject.put("issueKeys", "ABC-1");
            noProject.put("projectName", "");
            assertEquals("40004", run(noProject, FakeJiraApp.SECRET).field("errorCode"));

            Map<String, String> noSecret = base(app);
            noSecret.put("issueKeys", "ABC-1");
            assertEquals("40003", run(noSecret, "").field("errorCode"));

            Map<String, String> badNumber = base(app);
            badNumber.put("issueKeys", "ABC-1");
            badNumber.put("buildNumber", "x");
            assertEquals("40004", run(badNumber, FakeJiraApp.SECRET).field("errorCode"));

            Map<String, String> badAction = base(app);
            badAction.put("issueKeys", "ABC-1");
            badAction.put("action", "issue");
            assertEquals("40001", run(badAction, FakeJiraApp.SECRET).field("errorCode"));

            assertTrue(app.requests().isEmpty(), "a refused input must not reach the network");
        }
    }

    @Test
    @DisplayName("${VAR} in the inputs is expanded from the build parameters")
    void variablesAreExpanded() throws Exception {
        try (FakeJiraApp app = FakeJiraApp.start("accept")) {
            Map<String, String> params = base(app);
            params.put("projectName", "${JOB_NAME}");
            params.put("buildNumber", "${BUILD_NUMBER}");
            params.put("issueKeys", "ABC-1");
            params.put("JOB_NAME", "team/nightly");
            params.put("BUILD_NUMBER", "77");

            AtomResult run = run(params, FakeJiraApp.SECRET);
            Map<String, Object> body = payload(run, app, "team/nightly", "successful", 77);

            assertEquals(String.valueOf("team/nightly".hashCode()), body.get("pipelineId"));
            assertEquals(77, number(build(body).get("buildNumber")));
            run.assertOk();
        }
    }

    @Test
    @DisplayName("a deployment event: sequence number, environment, associations, and no commands unless gating is on")
    void deploymentBasic() throws Exception {
        try (FakeJiraApp app = FakeJiraApp.start("accept")) {
            Map<String, String> params = base(app);
            params.put("action", "deployment");
            params.put("environmentId", "env-1");
            params.put("environmentName", "Staging");
            params.put("environmentType", "staging");
            params.put("branch", "release/ABC-7");

            AtomResult run = run(params, FakeJiraApp.SECRET);
            run.assertOk();
            Map<String, Object> body = app.requests().get(app.requests().size() - 1).body();

            assertEquals("deployment", body.get("eventType"));
            assertEquals(String.valueOf("acme/service-api".hashCode()), body.get("pipelineId"));
            Map<String, Object> deployment = map(list(map(body.get("payload")).get("deployments")).get(0));
            assertEquals(42, number(deployment.get("deploymentSequenceNumber")));
            Map<String, Object> environment = map(deployment.get("environment"));
            assertEquals("env-1", environment.get("id"));
            assertEquals("Staging", environment.get("displayName"));
            assertEquals("staging", environment.get("type"));
            List<Map<String, Object>> associations = maps(deployment.get("associations"));
            assertEquals(1, associations.size());
            assertEquals("issueKeys", associations.get(0).get("associationType"));
            assertEquals(List.of("ABC-7"), strings(associations.get(0).get("values")));
            assertTrue(String.valueOf(map(deployment.get("pipeline")).get("url"))
                    .endsWith("/job/acme/job/service-api/"), String.valueOf(map(deployment.get("pipeline")).get("url")));
            assertFalse(deployment.containsKey("commands"));
            assertEquals("1", run.field("accepted"));
        }
    }

    @Test
    @DisplayName("gating asks the app to start, and service ids are attached sorted")
    void deploymentGatingAndServices() throws Exception {
        try (FakeJiraApp app = FakeJiraApp.start("accept")) {
            Map<String, String> params = base(app);
            params.put("action", "deployment");
            params.put("environmentId", "env-1");
            params.put("environmentName", "Prod");
            params.put("environmentType", "production");
            params.put("serviceIds", "svc-b,svc-a");
            params.put("issueKeys", "ABC-1");
            params.put("enableGating", "true");
            params.put("state", "in_progress");

            AtomResult run = run(params, FakeJiraApp.SECRET);
            run.assertOk();
            Map<String, Object> body = app.requests().get(app.requests().size() - 1).body();
            Map<String, Object> deployment = map(list(map(body.get("payload")).get("deployments")).get(0));

            List<Map<String, Object>> commands = maps(deployment.get("commands"));
            assertEquals(1, commands.size());
            assertEquals("initiate_deployment_gating", commands.get(0).get("command"));

            List<Map<String, Object>> associations = maps(deployment.get("associations"));
            assertEquals(2, associations.size());
            assertEquals("issueKeys", associations.get(0).get("associationType"));
            assertEquals(List.of("ABC-1"), strings(associations.get(0).get("values")));
            assertEquals("serviceIdOrKeys", associations.get(1).get("associationType"));
            assertEquals(List.of("svc-a", "svc-b"), strings(associations.get(1).get("values")));
            assertEquals("in_progress", deployment.get("state"));
        }
    }

    @Test
    @DisplayName("an environment without a name, or with a type the app does not have, is refused by name")
    void deploymentEnvironmentIsValidated() throws Exception {
        try (FakeJiraApp app = FakeJiraApp.start("accept")) {
            Map<String, String> noName = base(app);
            noName.put("action", "deployment");
            noName.put("environmentId", "env-1");
            noName.put("issueKeys", "ABC-1");

            AtomResult missingName = run(noName, FakeJiraApp.SECRET);
            missingName.assertRefused();
            assertEquals("40007", missingName.field("errorCode"), missingName.toString());
            assertTrue(missingName.field("message").contains("environmentName"), missingName.field("message"));

            Map<String, String> badType = base(app);
            badType.put("action", "deployment");
            badType.put("environmentId", "env-1");
            badType.put("environmentName", "Prod");
            badType.put("environmentType", "prod");
            badType.put("issueKeys", "ABC-1");

            AtomResult unmapped = run(badType, FakeJiraApp.SECRET);
            unmapped.assertRefused();
            assertEquals("40007", unmapped.field("errorCode"), unmapped.toString());
            assertTrue(unmapped.field("message").contains("unmapped"), unmapped.field("message"));
            assertTrue(app.requests().isEmpty(), "a refused deployment must not reach the network");
        }
    }

    @Test
    @DisplayName("a deployment with nothing to associate is skipped, not sent")
    void deploymentWithNothingToAssociateIsSkipped() throws Exception {
        try (FakeJiraApp app = FakeJiraApp.start("accept")) {
            Map<String, String> params = base(app);
            params.put("action", "deployment");
            params.put("environmentId", "env-1");
            params.put("environmentName", "Prod");
            params.put("branch", "");

            AtomResult run = run(params, FakeJiraApp.SECRET);

            run.assertOk();
            assertEquals("true", run.field("skipped"), run.toString());
            assertTrue(app.requests().isEmpty());
        }
    }

    @Test
    @DisplayName("a wrong secret is a 401 from the app, reported as an error")
    void jwtIsRefusedByTheApp() throws Exception {
        try (FakeJiraApp app = FakeJiraApp.start("accept")) {
            Map<String, String> params = base(app);
            params.put("issueKeys", "ABC-1");

            AtomResult run = run(params, "not-the-secret");

            run.assertRefused();
            assertEquals("40009", run.field("errorCode"), run.toString());
            assertTrue(run.field("message").contains("401"), run.field("message"));
            assertEquals("signature", app.requests().get(0).error());
        }
    }

    @Test
    @DisplayName("the app's answers are classified: rejected, unknown keys, nothing accepted, bad JSON, HTTP 400")
    void appErrorsAreReported() throws Exception {
        String[][] modes = {{"reject", "40013"}, {"unknown", "40014"}, {"empty", "40012"},
                {"bad-json", "40011"}, {"http-400", "40009"}};
        for (String[] mode : modes) {
            try (FakeJiraApp app = FakeJiraApp.start(mode[0])) {
                Map<String, String> params = base(app);
                params.put("issueKeys", "ABC-1");

                AtomResult run = run(params, FakeJiraApp.SECRET);
                run.assertRefused();
                assertEquals(mode[1], run.field("errorCode"), mode[0] + ": " + run);
            }
        }

        try (FakeJiraApp app = FakeJiraApp.start("http-400")) {
            Map<String, String> params = base(app);
            params.put("issueKeys", "ABC-1");

            AtomResult run = run(params, FakeJiraApp.SECRET);
            assertTrue(run.field("message").contains("the app says no"), run.field("message"));
        }
    }

    @Test
    @DisplayName("an app that is not listening is a third-party error, not a user error")
    void unreachableAppIsAThirdPartyError() throws Exception {
        int port;
        try (java.net.ServerSocket socket = new java.net.ServerSocket(0)) {
            port = socket.getLocalPort();
        }
        Map<String, String> params = new LinkedHashMap<>();
        params.put("action", "build");
        params.put("webhookUrl", "http://127.0.0.1:" + port + "/jenkins-forge-app");
        params.put("projectName", "acme/service-api");
        params.put("buildNumber", "42");
        params.put("buildUrl", "http://jenkins.example.com/job/acme/job/service-api/42/");
        params.put("label", "#42");
        params.put("BUILD_STATUS", "SUCCESS");
        params.put("issueKeys", "ABC-1");

        AtomResult run = run(params, FakeJiraApp.SECRET);

        run.assertRefused();
        assertEquals("40010", run.field("errorCode"), run.toString());
    }

    // ------------------------------------------------------------------ fixtures and helpers

    private static Map<String, String> base(FakeJiraApp app) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("action", "build");
        params.put("webhookUrl", app.webhookUrl());
        params.put("projectName", "acme/service-api");
        params.put("buildNumber", "42");
        params.put("buildUrl", "http://jenkins.example.com/job/acme/job/service-api/42/");
        params.put("label", "#42");
        params.put("BUILD_STATUS", "SUCCESS");
        return params;
    }

    private AtomResult run(Map<String, String> params, String secret) throws Exception {
        String secrets = secret.isEmpty() ? "{}" : "{\"secret\": \"" + secret + "\"}";
        return Atom.of()
                .file(".secrets.json", secrets)
                .input(json(params))
                .run();
    }

    /** The one request the app received, judged the way check.py judged it. */
    private static Map<String, Object> payload(AtomResult run, FakeJiraApp app) {
        return payload(run, app, "acme/service-api", "successful");
    }

    private static Map<String, Object> payload(AtomResult run, FakeJiraApp app, String project, String state) {
        return payload(run, app, project, state, 42);
    }

    private static Map<String, Object> payload(
            AtomResult run, FakeJiraApp app, String project, String state, int buildNumber) {
        run.assertOk();
        assertEquals(1, app.requests().size(), "expected one request, got " + app.requests().size());
        FakeJiraApp.Request request = app.requests().get(0);
        assertNull(request.error(), String.valueOf(request.error()));
        assertEquals("application/jwt", request.contentType());

        Map<String, Object> body = request.body();
        assertEquals(String.valueOf(project.hashCode()), String.valueOf(body.get("pipelineId")));
        assertEquals(project, body.get("pipelineName"));
        assertEquals(state, body.get("status"));

        Map<String, Object> build = build(body);
        assertEquals(String.valueOf(project.hashCode()), String.valueOf(build.get("pipelineId")));
        assertEquals(buildNumber, number(build.get("buildNumber")));
        assertEquals(state, build.get("state"));
        assertEquals(project, build.get("displayName"));
        assertEquals("#42", build.get("label"));
        assertTrue(Math.abs(number(build.get("updateSequenceNumber")) - System.currentTimeMillis() / 1000) < 300,
                String.valueOf(build.get("updateSequenceNumber")));
        assertTrue(String.valueOf(build.get("lastUpdated"))
                .matches("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$"), String.valueOf(build.get("lastUpdated")));
        assertEquals(String.valueOf(project.hashCode()), run.field("pipelineId"));
        return body;
    }

    private static Map<String, Object> build(Map<String, Object> body) {
        return map(list(map(body.get("payload")).get("builds")).get(0));
    }

    private static List<String> strings(Object value) {
        List<String> out = new ArrayList<>();
        for (Object item : list(value)) {
            out.add(String.valueOf(item));
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> maps(Object value) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object item : list(value)) {
            out.add((Map<String, Object>) item);
        }
        return out;
    }

    private static String json(Map<String, String> params) {
        StringBuilder out = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (!first) {
                out.append(", ");
            }
            first = false;
            out.append('"').append(entry.getKey()).append("\": \"")
                    .append(entry.getValue().replace("\\", "\\\\").replace("\"", "\\\""))
                    .append('"');
        }
        return out.append('}').toString();
    }
}
