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
package net.maritimeconnectivity.identityregistry.keycloak.spi.emailotp.resource;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import net.maritimeconnectivity.identityregistry.keycloak.spi.emailotp.core.EmailOtpPolicy;
import net.maritimeconnectivity.identityregistry.keycloak.spi.emailotp.core.OtpGenerator;
import net.maritimeconnectivity.identityregistry.keycloak.spi.emailotp.core.OtpHasher;
import net.maritimeconnectivity.identityregistry.keycloak.spi.emailotp.core.OtpRateLimitException;
import net.maritimeconnectivity.identityregistry.keycloak.spi.emailotp.core.OtpStore;
import org.jboss.logging.Logger;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.time.Clock;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class OtpResource {

    private static final Logger logger = Logger.getLogger(OtpResource.class);

    private static final String TEMPLATE_OTP = "email-otp.ftl";
    private static final String SUBJECT_KEY = "emailOtpSubject";

    private static final String ATTR_OTP = "otp";
    private static final String ATTR_TTL_MINUTES = "ttlMinutes";

    private static final String USERS_REALM_NAME = "Users";
    private static final String ATTR_MRN = "mrn";
    private static final List<String> COPIED_ATTRS = Arrays.asList(
            "mrn", "org", "uid", "permissions", "subsidiary_mrn", "mms_url"
    );

    private final KeycloakSession session;

    public OtpResource(KeycloakSession session) {
        this.session = session;
    }

    @POST
    @Path("send")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response send(OtpSendRequest body) {
        if (body == null || body.email == null || body.email.isBlank()) {
            return errorJson(Response.Status.BAD_REQUEST, "invalid_request",
                    "email is required", null);
        }

        String email = body.email.trim();
        RealmModel realm = session.getContext().getRealm();
        EmailOtpPolicy policy = EmailOtpPolicy.load();
        long now = Clock.systemUTC().instant().getEpochSecond();

        // MIR creates signup users only in the Users realm. Promote to MCP realm on first OTP send
        // so verify can find them and issue a MCP-realm JWT (which is what the app trusts).
        ensureMcpRealmUser(realm, email);

        UserModel user = session.users().getUserByEmail(realm, email);
        if (user == null || !user.isEnabled()) {
            return Response.ok(syntheticResponse(now, policy))
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .build();
        }

        OtpStore store = new OtpStore(session);
        String otp = OtpGenerator.generate(policy.length());
        String otpHash = OtpHasher.sha256Hex(otp);

        OtpStore.Issued issued;
        try {
            issued = store.issue(email, otpHash, policy);
        } catch (OtpRateLimitException e) {
            Map<String, Object> extra = new LinkedHashMap<>();
            extra.put("reason", e.getReason().name().toLowerCase());
            extra.put("retryAfter", e.getRetryAfter());
            return errorJson(Response.Status.TOO_MANY_REQUESTS, "rate_limited",
                    "Too many OTP requests", extra);
        }

        try {
            sendEmail(realm, user, otp, policy);
        } catch (EmailException e) {
            logger.errorf(e, "Failed to send OTP email to %s", email);
            return errorJson(Response.Status.BAD_GATEWAY, "email_send_failed",
                    "Failed to deliver OTP email", null);
        }

        return Response.ok(new OtpSendResponse(
                issued.expiresAt(),
                issued.resendAvailableAt(),
                issued.maxAttempts(),
                issued.serverTime()
        )).type(MediaType.APPLICATION_JSON_TYPE).build();
    }

    private void ensureMcpRealmUser(RealmModel mcpRealm, String email) {
        RealmModel usersRealm = session.realms().getRealmByName(USERS_REALM_NAME);
        if (usersRealm == null) {
            return;
        }
        UserModel usersRealmUser = session.users().getUserByEmail(usersRealm, email);
        if (usersRealmUser == null || !usersRealmUser.isEnabled() || usersRealmUser.isEmailVerified()) {
            return;
        }
        String mrn = usersRealmUser.getFirstAttribute(ATTR_MRN);
        if (mrn == null || mrn.isBlank()) {
            return;
        }
        if (session.users().getUserByUsername(mcpRealm, mrn) != null) {
            return;
        }
        UserModel mcpRealmUser = session.users().addUser(mcpRealm, mrn);
        mcpRealmUser.setEnabled(true);
        mcpRealmUser.setEmail(email);
        mcpRealmUser.setFirstName(usersRealmUser.getFirstName());
        mcpRealmUser.setLastName(usersRealmUser.getLastName());
        mcpRealmUser.setEmailVerified(false);
        for (String attrName : COPIED_ATTRS) {
            List<String> values = usersRealmUser.getAttributeStream(attrName).toList();
            if (!values.isEmpty()) {
                mcpRealmUser.setAttribute(attrName, values);
            }
        }
        logger.debugf("Pre-provisioned MCP realm user for OTP: mrn=%s email=%s", mrn, email);
    }

    private void sendEmail(RealmModel realm, UserModel user, String otp, EmailOtpPolicy policy) throws EmailException {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTR_OTP, otp);
        attributes.put(ATTR_TTL_MINUTES, policy.ttlSeconds() / 60);

        session.getProvider(EmailTemplateProvider.class)
                .setRealm(realm)
                .setUser(user)
                .send(SUBJECT_KEY, TEMPLATE_OTP, attributes);
    }

    private OtpSendResponse syntheticResponse(long now, EmailOtpPolicy policy) {
        return new OtpSendResponse(
                now + policy.ttlSeconds(),
                now + policy.resendCooldownSeconds(),
                policy.maxAttempts(),
                now
        );
    }

    private Response errorJson(Response.Status status, String error, String description, Map<String, Object> extra) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        body.put("error_description", description);
        if (extra != null) {
            body.putAll(extra);
        }
        return Response.status(status).entity(body).type(MediaType.APPLICATION_JSON_TYPE).build();
    }
}
