package atom;

import com.jenkinschina.atom.sdk.Json;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * The Jira app the atom talks to, faked: it verifies the JWT the way the app does (HS256 over the shared secret,
 * iss/aud, a five-minute expiry), records the request, and answers according to {@code mode}.
 *
 * <p>This is the same server {@code tools/check.py} runs, in Java, so the tests can judge the payload themselves.
 */
final class FakeJiraApp implements AutoCloseable {

    static final String SECRET = "sh4red-s3cret";

    private static final List<String> STATES =
            List.of("unknown", "pending", "in_progress", "cancelled", "failed", "rolled_back", "successful");
    private static final List<String> ENV_TYPES =
            List.of("development", "testing", "staging", "production", "unmapped");

    /** One request as the app saw it: the content type, the decoded event, and the JWT problem if there was one. */
    record Request(String path, String contentType, Map<String, Object> body, String error) {}

    private final HttpServer server;
    private final List<Request> requests = Collections.synchronizedList(new ArrayList<>());

    private FakeJiraApp(HttpServer server) {
        this.server = server;
    }

    static FakeJiraApp start(String mode) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        FakeJiraApp app = new FakeJiraApp(server);
        server.createContext("/", exchange -> app.handle(exchange, mode));
        server.start();
        return app;
    }

    int port() {
        return server.getAddress().getPort();
    }

    String baseUrl() {
        return "http://127.0.0.1:" + port();
    }

    String webhookUrl() {
        return baseUrl() + "/jenkins-forge-app";
    }

    List<Request> requests() {
        return List.copyOf(requests);
    }

    @Override
    public void close() {
        server.stop(0);
    }

    // ------------------------------------------------------------------ the handler

    private void handle(HttpExchange exchange, String mode) throws IOException {
        String raw = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        Map<String, Object> body = null;
        String error;
        try {
            String[] parts = raw.split("\\.");
            if (parts.length != 3) {
                throw new IllegalArgumentException("not a JWT: " + raw.length() + " chars");
            }
            Map<String, Object> header = Json.parseObject(new String(base64(parts[0]), StandardCharsets.UTF_8));
            Map<String, Object> claims = Json.parseObject(new String(base64(parts[1]), StandardCharsets.UTF_8));
            byte[] expected = hmac(parts[0] + "." + parts[1]);
            if (!java.security.MessageDigest.isEqual(expected, base64(parts[2]))) {
                error = "signature";
            } else if (!"HS256".equals(header.get("alg"))) {
                error = "alg " + header.get("alg");
            } else if (!"jenkins-plugin".equals(claims.get("iss")) || !"jenkins-forge-app".equals(claims.get("aud"))) {
                error = "claims iss=" + claims.get("iss") + " aud=" + claims.get("aud");
            } else if (number(claims.get("exp")) - number(claims.get("iat")) != 300) {
                error = "expiry " + (number(claims.get("exp")) - number(claims.get("iat")));
            } else {
                body = Json.parseObject(String.valueOf(claims.get("request_body_json")));
                error = validateEvent(body);
            }
        } catch (Exception e) {
            error = "unparseable: " + e.getMessage();
        }

        requests.add(new Request(exchange.getRequestURI().getPath(), contentType, body, error));
        if (error != null) {
            answer(exchange, 401, "{\"errorMessages\": [\"" + error.replace("\"", "'") + "\"]}");
            return;
        }

        boolean build = "build".equals(body.get("eventType"));
        switch (mode) {
            case "reject" -> answer(exchange, 200, build
                    ? "{\"acceptedBuilds\": [], \"rejectedBuilds\": [{\"errors\": [\"state not allowed\"]}],"
                            + " \"unknownIssueKeys\": []}"
                    : "{\"acceptedDeployments\": [], \"rejectedDeployments\": [{\"errors\": [\"nope\"]}],"
                            + " \"unknownAssociations\": []}");
            case "unknown" -> answer(exchange, 200, build
                    ? "{\"acceptedBuilds\": [], \"rejectedBuilds\": [], \"unknownIssueKeys\": [\"ZZZ-1\"]}"
                    : "{\"acceptedDeployments\": [], \"rejectedDeployments\": [],"
                            + " \"unknownAssociations\": [{\"associationType\": \"issueKeys\","
                            + " \"values\": [\"ZZZ-1\"]}]}");
            case "empty" -> answer(exchange, 200, build
                    ? "{\"acceptedBuilds\": [], \"rejectedBuilds\": [], \"unknownIssueKeys\": []}"
                    : "{\"acceptedDeployments\": [], \"rejectedDeployments\": [], \"unknownAssociations\": []}");
            case "bad-json" -> answer(exchange, 200, "not json at all");
            case "http-400" -> answer(exchange, 400, "{\"errorMessages\": [\"the app says no\"]}");
            default -> {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("id", 4242);
                entry.put("pipelineId", body.get("pipelineId"));
                List<?> items = build ? list(map(body.get("payload")).get("builds")) : list(map(body.get("payload")).get("deployments"));
                Object number = build ? map(items.get(0)).get("buildNumber") : map(items.get(0)).get("deploymentSequenceNumber");
                entry.put(build ? "buildNumber" : "deploymentSequenceNumber", number);
                Map<String, Object> response = new LinkedHashMap<>();
                response.put(build ? "acceptedBuilds" : "acceptedDeployments", List.of(entry));
                response.put(build ? "rejectedBuilds" : "rejectedDeployments", List.of());
                response.put(build ? "unknownIssueKeys" : "unknownAssociations", List.of());
                answer(exchange, 201, Json.write(response));
            }
        }
    }

    private static void answer(HttpExchange exchange, int status, String payload) throws IOException {
        byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    // ------------------------------------------------------------------ the app's own contract

    static String validateEvent(Map<String, Object> body) {
        if (!"event".equals(body.get("requestType"))) {
            return "requestType " + body.get("requestType");
        }
        String kind = String.valueOf(body.get("eventType"));
        if (!"build".equals(kind) && !"deployment".equals(kind)) {
            return "eventType " + kind;
        }
        for (String field : List.of("pipelineId", "pipelineName", "status", "lastUpdated", "payload")) {
            if (!body.containsKey(field)) {
                return "missing " + field;
            }
        }
        if (!STATES.contains(String.valueOf(body.get("status")))) {
            return "status " + body.get("status");
        }
        Map<String, Object> payload = map(body.get("payload"));
        if (!"jenkins".equals(map(payload.get("properties")).get("source"))) {
            return "properties.source";
        }
        if (!"jenkins".equals(map(payload.get("providerMetadata")).get("product"))) {
            return "providerMetadata.product";
        }
        List<?> items = list(payload.get("build".equals(kind) ? "builds" : "deployments"));
        if (items.size() != 1) {
            return "wrong number of " + kind + "s: " + items;
        }
        Map<String, Object> item = map(items.get(0));
        String pipelineId = String.valueOf(item.getOrDefault("pipelineId",
                map(item.get("pipeline")).getOrDefault("id", "")));
        if (pipelineId.isBlank()) {
            return "pipeline id missing";
        }
        if ("build".equals(kind)) {
            if (!"1.0".equals(item.get("schemaVersion"))) {
                return "schemaVersion " + item.get("schemaVersion");
            }
            if (!(item.get("buildNumber") instanceof Number)) {
                return "buildNumber " + item.get("buildNumber");
            }
            if (!String.valueOf(body.get("status")).equals(item.get("state"))) {
                return "build state differs from the envelope";
            }
            for (Object key : list(item.get("issueKeys"))) {
                if (!String.valueOf(key).matches("^[A-Z][A-Z0-9_]{1,255}-[0-9]{1,100}$")) {
                    return "issueKeys " + item.get("issueKeys");
                }
            }
            Map<String, Object> info = item.get("testInfo") == null ? null : map(item.get("testInfo"));
            if (info != null) {
                long passed = number(info.get("numberPassed"));
                long expected = Math.max(0, number(info.get("totalNumber")) - number(info.get("numberFailed"))
                        - number(info.get("numberSkipped")));
                if (passed != expected) {
                    return "testInfo passed does not add up: " + Json.write(info);
                }
            }
        } else {
            Map<String, Object> environment = map(item.get("environment"));
            if (isBlank(environment.get("id")) || isBlank(environment.get("displayName"))
                    || !ENV_TYPES.contains(String.valueOf(environment.get("type")))) {
                return "environment " + Json.write(environment);
            }
            if (!(item.get("deploymentSequenceNumber") instanceof Number)) {
                return "deploymentSequenceNumber " + item.get("deploymentSequenceNumber");
            }
            for (Object value : list(item.get("associations"))) {
                Map<String, Object> association = map(value);
                String type = String.valueOf(association.get("associationType"));
                if (!"issueKeys".equals(type) && !"serviceIdOrKeys".equals(type)) {
                    return "association " + Json.write(association);
                }
                if (list(association.get("values")).isEmpty()) {
                    return "association " + Json.write(association);
                }
            }
            if (!String.valueOf(body.get("pipelineId")).equals(String.valueOf(map(item.get("pipeline")).get("id")))) {
                return "pipeline id differs from the envelope";
            }
        }
        return null;
    }

    // ------------------------------------------------------------------ helpers

    private static byte[] hmac(String text) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return mac.doFinal(text.getBytes(StandardCharsets.UTF_8));
    }

    /** Base64url, padding optional — the atom writes what the app accepts. */
    private static byte[] base64(String part) {
        return Base64.getUrlDecoder().decode(part);
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> map(Object value) {
        return value instanceof Map<?, ?> ? (Map<String, Object>) value : Map.of();
    }

    static List<?> list(Object value) {
        return value instanceof List<?> items ? items : List.of();
    }

    static long number(Object value) {
        return value instanceof Number n ? n.longValue() : Long.parseLong(String.valueOf(value));
    }

    private static boolean isBlank(Object value) {
        return value == null || String.valueOf(value).isBlank();
    }
}
