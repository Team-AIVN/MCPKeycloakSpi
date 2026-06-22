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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class GraphMailClient {

    private static final String SEND_MAIL_URL = "https://graph.microsoft.com/v1.0/users/%s/sendMail";

    private final GraphTokenClient tokenClient;
    private final String fromAddress;
    private final HttpClient http;
    private final ObjectMapper mapper = new ObjectMapper();

    public GraphMailClient(GraphTokenClient tokenClient, String fromAddress) {
        this.tokenClient = tokenClient;
        this.fromAddress = fromAddress;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    public void send(String toAddress, String subject, String textBody, String htmlBody) throws IOException, InterruptedException {
        String token = tokenClient.getToken();
        String body = buildBody(toAddress, subject, textBody, htmlBody);

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(String.format(SEND_MAIL_URL, fromAddress)))
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(15))
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() / 100 != 2) {
            throw new IOException("Graph sendMail failed: " + resp.statusCode() + " " + resp.body());
        }
    }

    private String buildBody(String toAddress, String subject, String textBody, String htmlBody) throws IOException {
        boolean useHtml = htmlBody != null && !htmlBody.isBlank();
        String content = useHtml ? htmlBody : (textBody == null ? "" : textBody);
        String contentType = useHtml ? "HTML" : "Text";

        ObjectNode root = mapper.createObjectNode();
        ObjectNode message = root.putObject("message");
        message.put("subject", subject);

        ObjectNode messageBody = message.putObject("body");
        messageBody.put("contentType", contentType);
        messageBody.put("content", content);

        ArrayNode recipients = message.putArray("toRecipients");
        ObjectNode recipient = recipients.addObject();
        ObjectNode emailAddress = recipient.putObject("emailAddress");
        emailAddress.put("address", toAddress);

        root.put("saveToSentItems", false);

        return mapper.writeValueAsString(root);
    }
}
