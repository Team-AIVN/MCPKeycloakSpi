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

import com.fasterxml.jackson.annotation.JsonProperty;

public class OtpSendResponse {

    @JsonProperty("expiresAt")
    public long expiresAt;

    @JsonProperty("resendAvailableAt")
    public long resendAvailableAt;

    @JsonProperty("maxAttempts")
    public int maxAttempts;

    @JsonProperty("serverTime")
    public long serverTime;

    public OtpSendResponse() {
    }

    public OtpSendResponse(long expiresAt, long resendAvailableAt, int maxAttempts, long serverTime) {
        this.expiresAt = expiresAt;
        this.resendAvailableAt = resendAvailableAt;
        this.maxAttempts = maxAttempts;
        this.serverTime = serverTime;
    }
}
