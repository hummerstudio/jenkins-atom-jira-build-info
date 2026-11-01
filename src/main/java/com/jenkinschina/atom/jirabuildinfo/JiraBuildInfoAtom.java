
package com.jenkinschina.atom.jirabuildinfo;

import com.jenkinschina.atom.sdk.AtomContext;
import com.jenkinschina.atom.sdk.AtomResult;
import com.jenkinschina.atom.sdk.AtomTask;
import com.jenkinschina.atom.sdk.ErrorType;
import com.jenkinschina.atom.sdk.Json;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Send build or deployment information to the Jira Software Cloud app - the step half of the
 * atlassian-jira-software-cloud plugin.
 *
 * <p>The plugin has no REST client of its own for this: it POSTs a signed JWT to the webhook URL that the Jira
 * "Jenkins for Jira" app registered, with the event body inside the {@code request_body_json} claim. The signature is
 * HS256 over a shared secret, the claims are iss/aud/iat/exp, and the content type is {@code application/jwt} - see
 * {@code JenkinsAppApi#wrapInJwt} in the plugin. Reproducing that shape is the whole job; the payload itself is
 * {@code JiraBuildInfo}/{@code JiraDeploymentInfo}.
 *
 * <p>What this atom does differently, because a pipeline should not have to read a Jira wiki page:
 * issue keys are validated before the request (a run that names ABC-0 fails here, with the key, instead of coming back
 * as an "unknown issue key" three steps later), nulls are left out of the payload instead of being written as null
 * (Jackson writes them, Jira ignores them), and a run with nothing to associate to is reported as skipped rather than
 * silently successful.
 */
public class JiraBuildInfoAtom implements AtomTask {

    /** The plugin's ISSUE_KEY_MAX_LIMIT: Jira stops accepting associations past this many keys. */
    private static final int ISSUE_KEY_MAX_LIMIT = 100;

    private static final Pattern ISSUE_KEY = Pattern.compile(
            "(?:(?<=[\\s\\p{Punct}])|^)(\\p{Lu}[\\p{Lu}\\p{Digit}_]{1,255}-\\p{Digit}{1,100})(?:(?=[\\s\\p{Punct}])|$)");
    private static final Pattern EXPLICIT_ISSUE_KEY = Pattern.compile("^\\p{Lu}[\\p{Lu}\\p{Digit}_]{1,255}-\\p{Digit}{1,100}$");

    private static final Set<String> STATES =
            new LinkedHashSet<>(List.of("unknown", "pending", "in_progress", "cancelled", "failed", "rolled_back", "successful"));
    private static final Set<String> ENVIRONMENT_TYPES =
            new LinkedHashSet<>(List.of("development", "testing", "staging", "production", "unmapped"));

    private static final DateTimeFormatter ISO = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(java.time.ZoneOffset.UTC);

    @Override
    public AtomResult run(AtomContext context) throws Exception {
        String action = context.getParam("action", "build").trim().toLowerCase(Locale.ROOT);
        String webhookUrl = context.getParam("webhookUrl", "").trim();
        String secret = context.getSecret("secret");
        if (secret == null) {
            secret = context.getSecret("token");
        }
        if (secret == null) {
            secret = context.getParam("secret", "");
        }
        String projectName = expand(context, context.getParam("projectName", "")).trim();
        String buildUrl = expand(context, context.getParam("buildUrl", "")).trim();
        String label = expand(context, context.getParam("label", "")).trim();
        String stateParam = context.getParam("state", "").trim();
        String buildStatus = context.getParam("BUILD_STATUS", "").trim();
        String branch = expand(context, context.getParam("branch", "")).trim();
        String changeBranch = expand(context, context.getParam("changeBranch", "")).trim();
        String issueKeysParam = context.getParam("issueKeys", "").trim();
        int timeoutSeconds = Math.max(5, Math.min(context.getIntParam("timeoutSeconds", 30), 300));

        if (!action.equals("build") && !action.equals("deployment")) {
            return AtomResult.error(ErrorType.USER, 40001, "action must be build or deployment, not '" + action + "'");
        }
        if (webhookUrl.isEmpty()) {
            return AtomResult.error(ErrorType.USER, 40002,
                    "webhookUrl is required: it is the Jenkins app URL the Jira site shows when the app is connected");
        }
        URI webhook;
        try {
            webhook = URI.create(webhookUrl);
        } catch (IllegalArgumentException e) {
            return AtomResult.error(ErrorType.USER, 40002, "webhookUrl is not a URL: " + webhookUrl);
        }
        String scheme = webhook.getScheme() == null ? "" : webhook.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) {
            return AtomResult.error(ErrorType.USER, 40002, "webhookUrl must be http(s): " + webhookUrl);
        }
        if (secret == null || secret.isBlank()) {
            return AtomResult.error(ErrorType.USER, 40003, "the shared secret of the Jira app is required (it signs the JWT)");
        }
        if (projectName.isEmpty()) {
            return AtomResult.error(ErrorType.USER, 40004, "projectName is required: Jira keys builds by pipeline id, which is its hash");
        }
        int buildNumber = parseNumber(expand(context, context.getParam("buildNumber", "")));
        if (buildNumber < 0) {
            return AtomResult.error(ErrorType.USER, 40004, "buildNumber must be a non-negative integer");
        }

        String state = stateParam.isEmpty() ? stateOf(buildStatus) : stateParam;
        if (!STATES.contains(state)) {
            return AtomResult.error(ErrorType.USER, 40005,
                    "state '" + state + "' is not one of " + String.join(", ", STATES));
        }

        // ---- issue keys: explicit first, otherwise out of the branch names, like the plugin's extractors
        Set<String> issueKeys = new TreeSet<>();
        String[] explicit = issueKeysParam.isEmpty() ? new String[0] : issueKeysParam.split("[,\\s]+");
        for (String candidate : explicit) {
            if (candidate.isEmpty()) {
                continue;
            }
            if (!EXPLICIT_ISSUE_KEY.matcher(candidate).matches()) {
                return AtomResult.error(ErrorType.USER, 40006,
                        "issueKeys entry '" + candidate + "' is not a Jira issue key (expected e.g. ABC-123)");
            }
            issueKeys.add(candidate);
        }
        if (issueKeys.isEmpty()) {
            extractIssueKeys(branch, issueKeys);
            extractIssueKeys(changeBranch, issueKeys);
            extractIssueKeys(context.getParam("commitMessages", ""), issueKeys);
        }
        if (issueKeys.size() > ISSUE_KEY_MAX_LIMIT) {
            return AtomResult.error(ErrorType.USER, 40006,
                    "more than " + ISSUE_KEY_MAX_LIMIT + " issue keys (" + issueKeys.size() + "); Jira accepts at most " + ISSUE_KEY_MAX_LIMIT);
        }

        String pipelineId = String.valueOf(projectName.hashCode());
        String now = ISO.format(Instant.now());
        long epochSeconds = Instant.now().getEpochSecond();
        String displayName = label.isEmpty() ? projectName : label;

        Map<String, Object> payload = new LinkedHashMap<>();
        Map<String, Object> event = new LinkedHashMap<>();
        List<String> outputs = new ArrayList<>();

        if (action.equals("build")) {
            Map<String, Object> build = new LinkedHashMap<>();
            build.put("schemaVersion", "1.0");
            build.put("pipelineId", pipelineId);
            build.put("buildNumber", buildNumber);
            build.put("updateSequenceNumber", epochSeconds);
            build.put("displayName", projectName);
            build.put("label", displayName);
            if (!buildUrl.isEmpty()) {
                build.put("url", buildUrl);
            }
            String description = context.getParam("description", "").trim();
            if (!description.isEmpty()) {
                build.put("description", description);
            }
            build.put("state", state);
            build.put("lastUpdated", now);
            if (!issueKeys.isEmpty()) {
                build.put("issueKeys", new ArrayList<>(issueKeys));
            }
            Map<String, Object> testInfo = testInfo(context);
            if (testInfo != null) {
                build.put("testInfo", testInfo);
            }
            payload.put("builds", List.of(build));
            payload.put("properties", Map.of("source", "jenkins"));
            payload.put("providerMetadata", Map.of("product", "jenkins"));

            event.put("requestType", "event");
            event.put("eventType", "build");
            event.put("pipelineId", pipelineId);
            event.put("pipelineName", projectName);
            event.put("status", state);
            event.put("lastUpdated", now);
            event.put("payload", payload);

            if (issueKeys.isEmpty()) {
                context.log("[jira] skipped: no issue key in the inputs, branch names or commit messages");
                return AtomResult.success("skipped: nothing to associate the build with")
                        .data("action", "build")
                        .data("skipped", "true")
                        .data("pipelineId", pipelineId)
                        .data("state", state);
            }
        } else {
            String environmentId = context.getParam("environmentId", "").trim();
            String environmentName = context.getParam("environmentName", "").trim();
            String environmentType = context.getParam("environmentType", "").trim();
            if (environmentId.isEmpty() || environmentName.isEmpty()) {
                return AtomResult.error(ErrorType.USER, 40007,
                        "deployment needs environmentId and environmentName (Jira keys a deployment by environment id)");
            }
            if (environmentType.isEmpty()) {
                environmentType = "unmapped"; // the plugin's JENKINS-59862 fallback
            }
            if (!ENVIRONMENT_TYPES.contains(environmentType)) {
                return AtomResult.error(ErrorType.USER, 40007, "environmentType '" + environmentType
                        + "' is not one of " + String.join(", ", ENVIRONMENT_TYPES));
            }
            Set<String> serviceIds = new TreeSet<>();
            for (String service : context.getParam("serviceIds", "").split("[,\\s]+")) {
                if (!service.isBlank()) {
                    serviceIds.add(service.trim());
                }
            }
            if (issueKeys.isEmpty() && serviceIds.isEmpty()) {
                context.log("[jira] skipped: no issue key and no service id to associate the deployment with");
                return AtomResult.success("skipped: nothing to associate the deployment with")
                        .data("action", "deployment")
                        .data("skipped", "true")
                        .data("pipelineId", pipelineId)
                        .data("state", state);
            }

            List<Map<String, Object>> associations = new ArrayList<>();
            if (!issueKeys.isEmpty()) {
                associations.add(association("issueKeys", issueKeys));
            }
            if (!serviceIds.isEmpty()) {
                associations.add(association("serviceIdOrKeys", serviceIds));
            }

            Map<String, Object> pipeline = new LinkedHashMap<>();
            pipeline.put("id", pipelineId);
            pipeline.put("displayName", projectName);
            if (!buildUrl.isEmpty()) {
                pipeline.put("url", projectUrl(buildUrl));
            }

            Map<String, Object> environment = new LinkedHashMap<>();
            environment.put("id", environmentId);
            environment.put("displayName", environmentName);
            environment.put("type", environmentType);

            Map<String, Object> deployment = new LinkedHashMap<>();
            deployment.put("deploymentSequenceNumber", buildNumber);
            deployment.put("updateSequenceNumber", epochSeconds);
            deployment.put("associations", associations);
            deployment.put("displayName", displayName);
            if (!buildUrl.isEmpty()) {
                deployment.put("url", buildUrl);
            }
            deployment.put("description", displayName);
            deployment.put("lastUpdated", now);
            deployment.put("label", displayName);
            deployment.put("state", state);
            deployment.put("pipeline", pipeline);
            deployment.put("environment", environment);
            if (context.getBooleanParam("enableGating", false)) {
                deployment.put("commands", List.of(Map.of("command", "initiate_deployment_gating")));
            }
            payload.put("deployments", List.of(deployment));
            payload.put("properties", Map.of("source", "jenkins"));
            payload.put("providerMetadata", Map.of("product", "jenkins"));

            event.put("requestType", "event");
            event.put("eventType", "deployment");
            event.put("pipelineId", pipelineId);
            event.put("pipelineName", displayName);
            event.put("status", state);
            event.put("lastUpdated", now);
            event.put("payload", payload);
        }

        String body = Json.write(event);
        String jwt = sign(body, secret);
        context.log("[jira] " + action + " " + pipelineId + " #" + buildNumber + " state=" + state
                + " issueKeys=" + issueKeys + " -> " + webhookUrl);

        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(timeoutSeconds)).build();
        HttpRequest request = HttpRequest.newBuilder(webhook)
                .timeout(Duration.ofSeconds(timeoutSeconds))
                .header("Content-Type", "application/jwt")
                .POST(HttpRequest.BodyPublishers.ofString(jwt, StandardCharsets.UTF_8))
                .build();

        HttpResponse<String> response;
        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (java.io.IOException e) {
            return AtomResult.error(ErrorType.THIRD_PART, 40010,
                    "could not reach the Jira app at " + webhookUrl + ": " + e.getMessage());
        }

        String text = response.body() == null ? "" : response.body().trim();
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            return AtomResult.error(ErrorType.THIRD_PART, 40009,
                    "the Jira app answered HTTP " + response.statusCode() + ": " + abbreviate(text));
        }

        Map<String, Object> parsed;
        try {
            parsed = Json.parseObject(text);
        } catch (RuntimeException e) {
            return AtomResult.error(ErrorType.THIRD_PART, 40011,
                    "the Jira app answered something that is not JSON: " + abbreviate(text));
        }

        // Read back what the app says it took: accepted vs rejected is the only confirmation there is.
        String acceptedKey = action.equals("build") ? "acceptedBuilds" : "acceptedDeployments";
        String rejectedKey = action.equals("build") ? "rejectedBuilds" : "rejectedDeployments";
        String unknownKey = action.equals("build") ? "unknownIssueKeys" : "unknownAssociations";
        if (!parsed.containsKey(acceptedKey) && !parsed.containsKey(rejectedKey) && !parsed.containsKey(unknownKey)) {
            return AtomResult.error(ErrorType.THIRD_PART, 40012,
                    "the Jira app answered without " + acceptedKey + "/" + rejectedKey + ": " + abbreviate(text));
        }
        int accepted = size(parsed.get(acceptedKey));
        int rejected = size(parsed.get(rejectedKey));
        int unknown = size(parsed.get(unknownKey));
        String acceptedId = firstId(parsed.get(acceptedKey));
        if (acceptedId != null) {
            outputs.add(acceptedId);
        }

        if (rejected > 0) {
            return AtomResult.error(ErrorType.THIRD_PART, 40013,
                    "Jira rejected the " + action + " (" + rejected + "): " + abbreviate(Json.write(parsed.get(rejectedKey))));
        }
        if (accepted == 0 && unknown > 0) {
            return AtomResult.error(ErrorType.THIRD_PART, 40014, "Jira does not know these issue keys/services: "
                    + abbreviate(Json.write(parsed.get(unknownKey))));
        }
        if (accepted == 0) {
            return AtomResult.error(ErrorType.THIRD_PART, 40012,
                    "Jira accepted nothing and rejected nothing: " + abbreviate(text));
        }
        if (unknown > 0) {
            context.log("[jira] accepted, but Jira does not know " + abbreviate(Json.write(parsed.get(unknownKey))));
        }

        context.log("[jira] " + action + " accepted (" + accepted + ")");
        return AtomResult.success("Jira accepted the " + action)
                .data("action", action)
                .data("skipped", "false")
                .data("pipelineId", pipelineId)
                .data("state", state)
                .data("issueKeys", String.join(",", issueKeys))
                .data("accepted", String.valueOf(accepted))
                .data("unknownAssociations", String.valueOf(unknown))
                .data("httpStatus", String.valueOf(response.statusCode()));
    }

    /**
     * {@code ${NAME}} from the job's parameters or environment, so the task.json defaults can say {@code ${JOB_NAME}}
     * the way a Jenkinsfile does. An unresolved name is left alone rather than turning into an empty string.
     */
    static String expand(AtomContext context, String value) {
        if (value == null || value.indexOf("${") < 0) {
            return value == null ? "" : value;
        }
        Matcher matcher = Pattern.compile("\\$\\{([A-Za-z_][A-Za-z0-9_]*)}").matcher(value);
        StringBuilder sb = new StringBuilder();
        while (matcher.find()) {
            String name = matcher.group(1);
            String replacement = context.getParam(name);
            if (replacement == null) {
                replacement = System.getenv(name);
            }
            matcher.appendReplacement(sb, Matcher.quoteReplacement(replacement == null ? matcher.group() : replacement));
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    // ------------------------------------------------------------------ helpers

    private static Map<String, Object> association(String type, Set<String> values) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("associationType", type);
        map.put("values", new ArrayList<>(values));
        return map;
    }

    private static Map<String, Object> testInfo(AtomContext context) {
        int total = context.getIntParam("testsTotal", -1);
        if (total < 0) {
            return null;
        }
        int failed = Math.max(0, context.getIntParam("testsFailed", 0));
        int skipped = Math.max(0, context.getIntParam("testsSkipped", 0));
        int passed = Math.max(0, total - failed - skipped);
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("totalNumber", total);
        info.put("numberPassed", passed);
        info.put("numberFailed", failed);
        info.put("numberSkipped", skipped);
        return info;
    }

    /** {@code JenkinsToJiraStatus}: a build with no result yet is in progress; UNSTABLE has no Jira state of its own. */
    static String stateOf(String buildStatus) {
        if (buildStatus == null || buildStatus.isBlank()) {
            return "in_progress";
        }
        return switch (buildStatus.toUpperCase(Locale.ROOT)) {
            case "SUCCESS" -> "successful";
            case "FAILURE" -> "failed";
            case "ABORTED" -> "cancelled";
            default -> "unknown";
        };
    }

    static void extractIssueKeys(String text, Set<String> into) {
        if (text == null || text.isBlank()) {
            return;
        }
        Matcher matcher = ISSUE_KEY.matcher(text);
        while (matcher.find() && into.size() < ISSUE_KEY_MAX_LIMIT) {
            into.add(matcher.group(1));
        }
    }

    /** {@code <job url><build number>/} -> {@code <job url>}: the pipeline url is the job's, not the run's. */
    static String projectUrl(String buildUrl) {
        String trimmed = buildUrl.replaceAll("/+$", "");
        int slash = trimmed.lastIndexOf('/');
        if (slash > 0 && trimmed.substring(slash + 1).matches("\\d+")) {
            return trimmed.substring(0, slash + 1);
        }
        return trimmed.endsWith("/") ? trimmed : trimmed + "/";
    }

    /** auth0's {@code JWT.create()} with iss/aud/iat/exp and the body in {@code request_body_json}, HS256. */
    static String sign(String bodyJson, String secret) throws GeneralSecurityException {
        long iat = Instant.now().getEpochSecond();
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "HS256");
        header.put("typ", "JWT");
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", "jenkins-plugin");
        claims.put("aud", "jenkins-forge-app");
        claims.put("iat", iat);
        claims.put("exp", iat + 300);
        claims.put("request_body_json", bodyJson);
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String unsigned = encoder.encodeToString(Json.write(header).getBytes(StandardCharsets.UTF_8))
                + "." + encoder.encodeToString(Json.write(claims).getBytes(StandardCharsets.UTF_8));
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return unsigned + "." + encoder.encodeToString(mac.doFinal(unsigned.getBytes(StandardCharsets.US_ASCII)));
    }

    /** A build number from a string that may still carry {@code ${...}}; -1 when it is not a number. */
    static int parseNumber(String value) {
        try {
            return value == null || value.isBlank() ? -1 : Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private static int size(Object value) {
        return value instanceof List<?> list ? list.size() : 0;
    }

    private static String firstId(Object value) {
        if (value instanceof List<?> list && !list.isEmpty() && list.get(0) instanceof Map<?, ?> first) {
            for (String key : List.of("id", "buildKey", "deploymentKey", "pipelineId")) {
                Object found = first.get(key);
                if (found != null) {
                    return String.valueOf(found);
                }
            }
        }
        return null;
    }

    private static String abbreviate(String text) {
        if (text == null) {
            return "";
        }
        return text.length() <= 400 ? text : text.substring(0, 400) + "...";
    }
}
