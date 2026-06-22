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
package net.maritimeconnectivity.identityregistry.keycloak.spi.emailotp.grant;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import net.maritimeconnectivity.identityregistry.keycloak.spi.emailotp.core.OtpStore;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeBase;
import org.keycloak.services.Urls;
import org.keycloak.services.util.DefaultClientSessionContext;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

public class EmailOtpGrantType extends OAuth2GrantTypeBase {

    public static final String GRANT_TYPE = "email_otp";
    public static final String PARAM_EMAIL = "email";
    public static final String PARAM_OTP = "otp";

    @Override
    public EventType getEventType() {
        return EventType.LOGIN;
    }

    @Override
    public Response process(Context context) {
        setContext(context);
        event.detail(Details.AUTH_METHOD, GRANT_TYPE);

        String email = formParams.getFirst(PARAM_EMAIL);
        String otp = formParams.getFirst(PARAM_OTP);
        if (email == null || email.isBlank() || otp == null || otp.isBlank()) {
            event.error(Errors.INVALID_REQUEST);
            return errorJson("invalid_request", "Missing email or otp parameter", null,
                    Response.Status.BAD_REQUEST);
        }

        UserModel user = session.users().getUserByEmail(realm, email.trim());
        if (user == null) {
            event.error(Errors.USER_NOT_FOUND);
            return errorJson("invalid_grant", "Invalid email or OTP", null,
                    Response.Status.UNAUTHORIZED);
        }
        if (!user.isEnabled()) {
            event.error(Errors.USER_DISABLED);
            return errorJson("invalid_grant", "User is disabled", null,
                    Response.Status.UNAUTHORIZED);
        }

        OtpStore store = new OtpStore(session);
        OtpStore.VerifyResult result = store.verify(email, otp);
        switch (result.status()) {
            case SUCCESS -> {
            }
            case INVALID -> {
                event.error(Errors.INVALID_USER_CREDENTIALS);
                Map<String, Object> extra = new HashMap<>();
                extra.put("attempts_remaining", result.attemptsRemaining());
                return errorJson("invalid_grant", "Invalid OTP", extra,
                        Response.Status.UNAUTHORIZED);
            }
            case LOCKED -> {
                event.error(Errors.USER_TEMPORARILY_DISABLED);
                return errorJson("invalid_grant", "Too many invalid attempts", null,
                        Response.Status.UNAUTHORIZED);
            }
            case NOT_FOUND_OR_EXPIRED -> {
                event.error(Errors.INVALID_USER_CREDENTIALS);
                return errorJson("invalid_grant", "OTP expired or not issued", null,
                        Response.Status.UNAUTHORIZED);
            }
        }

        String scope = getRequestedScopes();

        UserSessionModel userSession = session.sessions().createUserSession(
                KeycloakModelUtils.generateId(),
                realm,
                user,
                user.getUsername(),
                clientConnection.getRemoteAddr(),
                GRANT_TYPE,
                false,
                null,
                null,
                UserSessionModel.SessionPersistenceState.PERSISTENT
        );
        updateUserSessionFromClientAuth(userSession);

        AuthenticatedClientSessionModel clientSession = session.sessions().createClientSession(realm, client, userSession);
        clientSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        clientSession.setNote(OIDCLoginProtocol.ISSUER,
                Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
        clientSession.setRedirectUri("");

        ClientSessionContext clientSessionCtx = DefaultClientSessionContext.fromClientSessionAndScopeParameter(
                clientSession, scope, session);

        event.user(user).session(userSession);

        return createTokenResponse(user, userSession, clientSessionCtx, scope, false, null);
    }

    private Response errorJson(String error, String description, Map<String, Object> extra,
                               Response.Status status) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        body.put("error_description", description);
        if (extra != null) {
            body.putAll(extra);
        }
        return cors.add(Response.status(status).entity(body).type(MediaType.APPLICATION_JSON_TYPE));
    }
}
