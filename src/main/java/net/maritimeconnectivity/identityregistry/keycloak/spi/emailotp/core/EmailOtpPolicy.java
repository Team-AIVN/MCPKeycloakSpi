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

public record EmailOtpPolicy(
        int length,
        long ttlSeconds,
        int maxAttempts,
        long resendCooldownSeconds,
        int hourlyLimit
) {
    public static final int DEFAULT_LENGTH = 6;
    public static final long DEFAULT_TTL_SECONDS = 300;
    public static final int DEFAULT_MAX_ATTEMPTS = 5;
    public static final long DEFAULT_RESEND_COOLDOWN_SECONDS = 60;
    public static final int DEFAULT_HOURLY_LIMIT = 5;

    public static EmailOtpPolicy load() {
        return new EmailOtpPolicy(
                envInt("EMAIL_OTP_LENGTH", DEFAULT_LENGTH),
                envLong("EMAIL_OTP_TTL_SECONDS", DEFAULT_TTL_SECONDS),
                envInt("EMAIL_OTP_MAX_ATTEMPTS", DEFAULT_MAX_ATTEMPTS),
                envLong("EMAIL_OTP_RESEND_COOLDOWN_SECONDS", DEFAULT_RESEND_COOLDOWN_SECONDS),
                envInt("EMAIL_OTP_HOURLY_LIMIT", DEFAULT_HOURLY_LIMIT)
        );
    }

    private static int envInt(String key, int defaultValue) {
        String v = System.getenv(key);
        if (v == null || v.isBlank()) return defaultValue;
        try {
            return Integer.parseInt(v.trim());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private static long envLong(String key, long defaultValue) {
        String v = System.getenv(key);
        if (v == null || v.isBlank()) return defaultValue;
        try {
            return Long.parseLong(v.trim());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }
}
