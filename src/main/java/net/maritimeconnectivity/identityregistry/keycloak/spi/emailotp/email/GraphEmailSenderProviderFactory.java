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

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.email.EmailSenderProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class GraphEmailSenderProviderFactory implements EmailSenderProviderFactory {

    private static final Logger logger = Logger.getLogger(GraphEmailSenderProviderFactory.class);

    public static final String PROVIDER_ID = "graph";

    private static final String ENV_TENANT_ID = "EMAIL_GRAPH_TENANT_ID";
    private static final String ENV_CLIENT_ID = "EMAIL_GRAPH_CLIENT_ID";
    private static final String ENV_CLIENT_SECRET = "EMAIL_GRAPH_CLIENT_SECRET";
    private static final String ENV_FROM_ADDRESS = "EMAIL_GRAPH_FROM_ADDRESS";

    private GraphMailClient client;

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public EmailSenderProvider create(KeycloakSession session) {
        if (client == null) {
            throw new IllegalStateException(
                    "Graph EmailSenderProvider not configured. Set "
                            + ENV_TENANT_ID + ", " + ENV_CLIENT_ID + ", "
                            + ENV_CLIENT_SECRET + ", " + ENV_FROM_ADDRESS + " env vars.");
        }
        return new GraphEmailSenderProvider(client);
    }

    @Override
    public void init(Config.Scope config) {
        String tenantId = env(ENV_TENANT_ID);
        String clientId = env(ENV_CLIENT_ID);
        String clientSecret = env(ENV_CLIENT_SECRET);
        String fromAddress = env(ENV_FROM_ADDRESS);

        if (tenantId == null || clientId == null || clientSecret == null || fromAddress == null) {
            logger.warn("Graph EmailSenderProvider env vars missing — provider will fail on first send. " +
                    "Set EMAIL_GRAPH_TENANT_ID, EMAIL_GRAPH_CLIENT_ID, EMAIL_GRAPH_CLIENT_SECRET, EMAIL_GRAPH_FROM_ADDRESS.");
            return;
        }

        GraphTokenClient tokenClient = new GraphTokenClient(tenantId, clientId, clientSecret);
        this.client = new GraphMailClient(tokenClient, fromAddress);
        logger.infof("Graph EmailSenderProvider initialized (from=%s)", fromAddress);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    private static String env(String key) {
        String v = System.getenv(key);
        return v == null || v.isBlank() ? null : v.trim();
    }
}
