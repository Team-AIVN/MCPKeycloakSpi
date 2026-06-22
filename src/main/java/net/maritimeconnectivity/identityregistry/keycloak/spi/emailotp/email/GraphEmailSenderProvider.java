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

import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;

import java.util.Map;

public class GraphEmailSenderProvider implements EmailSenderProvider {

    private final GraphMailClient client;

    public GraphEmailSenderProvider(GraphMailClient client) {
        this.client = client;
    }

    @Override
    public void send(Map<String, String> config, String address, String subject, String textBody, String htmlBody) throws EmailException {
        try {
            client.send(address, subject, textBody, htmlBody);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new EmailException("Interrupted while sending email via Graph API", e);
        } catch (Exception e) {
            throw new EmailException("Failed to send email via Graph API", e);
        }
    }

    @Override
    public void validate(Map<String, String> config) throws EmailException {
    }

    @Override
    public void close() {
    }
}
