/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.webauthn4j.util.AssertUtil;
import org.jetbrains.annotations.NotNull;

import java.util.Objects;

/**
 * This enumeration defines the capabilities that a WebAuthn Client can provide.
 * These values are returned by the PublicKeyCredential.getClientCapabilities() static method.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#enumdef-clientcapability">
 * §5.8.7. Client Capability Enumeration (enum ClientCapability)</a>
 */
public class ClientCapability {

    /**
     * The WebAuthn Client is capable of conditional mediation for registration ceremonies.
     */
    public static final ClientCapability CONDITIONAL_CREATE = new ClientCapability("conditionalCreate");

    /**
     * The WebAuthn Client is capable of conditional mediation for authentication ceremonies.
     */
    public static final ClientCapability CONDITIONAL_GET = new ClientCapability("conditionalGet");

    /**
     * The WebAuthn Client supports hybrid transport.
     */
    public static final ClientCapability HYBRID_TRANSPORT = new ClientCapability("hybridTransport");

    /**
     * The WebAuthn Client has a passkey platform authenticator available.
     */
    public static final ClientCapability PASSKEY_PLATFORM_AUTHENTICATOR = new ClientCapability("passkeyPlatformAuthenticator");

    /**
     * The WebAuthn Client has a user-verifying platform authenticator available.
     */
    public static final ClientCapability USER_VERIFYING_PLATFORM_AUTHENTICATOR = new ClientCapability("userVerifyingPlatformAuthenticator");

    /**
     * The WebAuthn Client supports related origins.
     */
    public static final ClientCapability RELATED_ORIGINS = new ClientCapability("relatedOrigins");

    /**
     * The WebAuthn Client supports signalAllAcceptedCredentials signal method.
     */
    public static final ClientCapability SIGNAL_ALL_ACCEPTED_CREDENTIALS = new ClientCapability("signalAllAcceptedCredentials");

    /**
     * The WebAuthn Client supports signalCurrentUserDetails signal method.
     */
    public static final ClientCapability SIGNAL_CURRENT_USER_DETAILS = new ClientCapability("signalCurrentUserDetails");

    /**
     * The WebAuthn Client supports signalUnknownCredential signal method.
     */
    public static final ClientCapability SIGNAL_UNKNOWN_CREDENTIAL = new ClientCapability("signalUnknownCredential");

    private final String value;

    private ClientCapability(@NotNull String value) {
        this.value = value;
    }

    @JsonCreator
    public static @NotNull ClientCapability create(@NotNull String value) {
        AssertUtil.notNull(value, "value must not be null.");
        switch (value) {
            case "conditionalCreate":
                return CONDITIONAL_CREATE;
            case "conditionalGet":
                return CONDITIONAL_GET;
            case "hybridTransport":
                return HYBRID_TRANSPORT;
            case "passkeyPlatformAuthenticator":
                return PASSKEY_PLATFORM_AUTHENTICATOR;
            case "userVerifyingPlatformAuthenticator":
                return USER_VERIFYING_PLATFORM_AUTHENTICATOR;
            case "relatedOrigins":
                return RELATED_ORIGINS;
            case "signalAllAcceptedCredentials":
                return SIGNAL_ALL_ACCEPTED_CREDENTIALS;
            case "signalCurrentUserDetails":
                return SIGNAL_CURRENT_USER_DETAILS;
            case "signalUnknownCredential":
                return SIGNAL_UNKNOWN_CREDENTIAL;
            default:
                return new ClientCapability(value);
        }
    }

    @JsonValue
    public @NotNull String getValue() {
        return value;
    }

    @Override
    public String toString() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ClientCapability that = (ClientCapability) o;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }
}
