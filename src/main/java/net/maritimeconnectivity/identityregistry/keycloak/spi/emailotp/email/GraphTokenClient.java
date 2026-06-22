/*
 * Copyright 2026 AIVeNautics
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package net.maritimeconnectivity.identityregistry.keycloak.spi.emailotp.email;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;

public class GraphTokenClient {

    private static final String TOKEN_URL = "https://login.microsoftonline.com/%s/oauth2/v2.0/token";
    private static final String SCOPE = "https://graph.microsoft.com/.default";
    private static final Duration REFRESH_MARGIN = Duration.ofSeconds(60);

    private final String tenantId;
    private final String clientId;
    private final String clientSecret;
    private final HttpClient http;
    private final ObjectMapper mapper = new ObjectMapper();

    private volatile CachedToken cached;

    public GraphTokenClient(String tenantId, String clientId, String clientSecret) {
        this.tenantId = tenantId;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    public synchronized String getToken() throws IOException, InterruptedException {
        if (cached != null && Instant.now().isBefore(cached.expiresAt.minus(REFRESH_MARGIN))) {
            return cached.token;
        }
        cached = fetch();
        return cached.token;
    }

    private CachedToken fetch() throws IOException, InterruptedException {
        String body = "client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + "&client_secret=" + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8)
                + "&scope=" + URLEncoder.encode(SCOPE, StandardCharsets.UTF_8)
                + "&grant_type=client_credentials";

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(String.format(TOKEN_URL, tenantId)))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .timeout(Duration.ofSeconds(10))
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() / 100 != 2) {
            throw new IOException("Azure AD token request failed: " + resp.statusCode() + " " + resp.body());
        }

        JsonNode json = mapper.readTree(resp.body());
        String token = json.get("access_token").asText();
        long expiresIn = json.get("expires_in").asLong();
        return new CachedToken(token, Instant.now().plusSeconds(expiresIn));
    }

    private record CachedToken(String token, Instant expiresAt) {
    }
}
