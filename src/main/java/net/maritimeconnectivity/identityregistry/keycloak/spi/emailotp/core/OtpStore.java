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
package net.maritimeconnectivity.identityregistry.keycloak.spi.emailotp.core;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;

import java.time.Clock;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public class OtpStore {

    private static final String KEY_RECORD_PREFIX = "email-otp:";
    private static final String KEY_RESEND_PREFIX = "email-otp-resend:";
    private static final String KEY_HOURLY_PREFIX = "email-otp-hourly:";

    private static final String NOTE_HASH = "hash";
    private static final String NOTE_ISSUED_AT = "issuedAt";
    private static final String NOTE_TTL_SECONDS = "ttlSeconds";
    private static final String NOTE_MAX_ATTEMPTS = "maxAttempts";
    private static final String NOTE_ATTEMPTS_USED = "attemptsUsed";
    private static final String NOTE_RESEND_AVAILABLE_AT = "resendAvailableAt";
    private static final String NOTE_COUNT = "count";

    private static final long HOURLY_WINDOW_SECONDS = 3600;

    private final SingleUseObjectProvider store;
    private final Clock clock;

    public OtpStore(KeycloakSession session) {
        this(session, Clock.systemUTC());
    }

    public OtpStore(KeycloakSession session, Clock clock) {
        this.store = session.singleUseObjects();
        this.clock = clock;
    }

    public Issued issue(String email, String otpHash, EmailOtpPolicy policy) throws OtpRateLimitException {
        String key = normalize(email);
        long now = clock.instant().getEpochSecond();

        Map<String, String> resend = store.get(KEY_RESEND_PREFIX + key);
        if (resend != null) {
            long resendAt = Long.parseLong(resend.get(NOTE_RESEND_AVAILABLE_AT));
            throw new OtpRateLimitException(OtpRateLimitException.Reason.COOLDOWN, resendAt);
        }

        Map<String, String> hourly = store.get(KEY_HOURLY_PREFIX + key);
        int hourlyCount = hourly == null ? 0 : Integer.parseInt(hourly.get(NOTE_COUNT));
        if (hourlyCount >= policy.hourlyLimit()) {
            throw new OtpRateLimitException(OtpRateLimitException.Reason.HOURLY_LIMIT, now + HOURLY_WINDOW_SECONDS);
        }

        store.remove(KEY_RECORD_PREFIX + key);

        Map<String, String> record = new HashMap<>();
        record.put(NOTE_HASH, otpHash);
        record.put(NOTE_ISSUED_AT, Long.toString(now));
        record.put(NOTE_TTL_SECONDS, Long.toString(policy.ttlSeconds()));
        record.put(NOTE_MAX_ATTEMPTS, Integer.toString(policy.maxAttempts()));
        record.put(NOTE_ATTEMPTS_USED, "0");
        store.put(KEY_RECORD_PREFIX + key, policy.ttlSeconds(), record);

        long resendAvailableAt = now + policy.resendCooldownSeconds();
        Map<String, String> resendMark = new HashMap<>();
        resendMark.put(NOTE_RESEND_AVAILABLE_AT, Long.toString(resendAvailableAt));
        store.remove(KEY_RESEND_PREFIX + key);
        store.put(KEY_RESEND_PREFIX + key, policy.resendCooldownSeconds(), resendMark);

        Map<String, String> newHourly = new HashMap<>();
        newHourly.put(NOTE_COUNT, Integer.toString(hourlyCount + 1));
        store.remove(KEY_HOURLY_PREFIX + key);
        store.put(KEY_HOURLY_PREFIX + key, HOURLY_WINDOW_SECONDS, newHourly);

        return new Issued(
                now + policy.ttlSeconds(),
                resendAvailableAt,
                policy.maxAttempts(),
                now
        );
    }

    public VerifyResult verify(String email, String otp) {
        String key = normalize(email);

        Map<String, String> record = store.get(KEY_RECORD_PREFIX + key);
        if (record == null) {
            return VerifyResult.notFoundOrExpired();
        }

        int maxAttempts = Integer.parseInt(record.get(NOTE_MAX_ATTEMPTS));
        int used = Integer.parseInt(record.get(NOTE_ATTEMPTS_USED));

        if (used >= maxAttempts) {
            return VerifyResult.locked();
        }

        String expectedHash = record.get(NOTE_HASH);
        String actualHash = OtpHasher.sha256Hex(otp);

        if (!constantTimeEquals(expectedHash, actualHash)) {
            int newUsed = used + 1;
            int remaining = maxAttempts - newUsed;
            Map<String, String> updated = new HashMap<>(record);
            updated.put(NOTE_ATTEMPTS_USED, Integer.toString(newUsed));
            store.replace(KEY_RECORD_PREFIX + key, updated);
            if (remaining <= 0) {
                return VerifyResult.locked();
            }
            return VerifyResult.invalid(remaining);
        }

        store.remove(KEY_RECORD_PREFIX + key);
        return VerifyResult.success();
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null || a.length() != b.length()) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }

    public static String normalize(String email) {
        return email == null ? "" : email.trim().toLowerCase(Locale.ROOT);
    }

    public record Issued(
            long expiresAt,
            long resendAvailableAt,
            int maxAttempts,
            long serverTime
    ) {
    }

    public record VerifyResult(Status status, Integer attemptsRemaining) {
        public enum Status {
            SUCCESS,
            INVALID,
            LOCKED,
            NOT_FOUND_OR_EXPIRED
        }

        public static VerifyResult success() {
            return new VerifyResult(Status.SUCCESS, null);
        }

        public static VerifyResult invalid(int remaining) {
            return new VerifyResult(Status.INVALID, remaining);
        }

        public static VerifyResult locked() {
            return new VerifyResult(Status.LOCKED, 0);
        }

        public static VerifyResult notFoundOrExpired() {
            return new VerifyResult(Status.NOT_FOUND_OR_EXPIRED, null);
        }
    }
}
