/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.data;

import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.exc.MismatchedInputException;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class ClientCapabilityTest {

    private final JsonMapper jsonMapper = new ObjectConverter().getJsonMapper();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(ClientCapability.create("conditionalCreate")).isEqualTo(ClientCapability.CONDITIONAL_CREATE),
                () -> assertThat(ClientCapability.create("conditionalGet")).isEqualTo(ClientCapability.CONDITIONAL_GET),
                () -> assertThat(ClientCapability.create("hybridTransport")).isEqualTo(ClientCapability.HYBRID_TRANSPORT),
                () -> assertThat(ClientCapability.create("passkeyPlatformAuthenticator")).isEqualTo(ClientCapability.PASSKEY_PLATFORM_AUTHENTICATOR),
                () -> assertThat(ClientCapability.create("userVerifyingPlatformAuthenticator")).isEqualTo(ClientCapability.USER_VERIFYING_PLATFORM_AUTHENTICATOR),
                () -> assertThat(ClientCapability.create("relatedOrigins")).isEqualTo(ClientCapability.RELATED_ORIGINS),
                () -> assertThat(ClientCapability.create("signalAllAcceptedCredentials")).isEqualTo(ClientCapability.SIGNAL_ALL_ACCEPTED_CREDENTIALS),
                () -> assertThat(ClientCapability.create("signalCurrentUserDetails")).isEqualTo(ClientCapability.SIGNAL_CURRENT_USER_DETAILS),
                () -> assertThat(ClientCapability.create("signalUnknownCredential")).isEqualTo(ClientCapability.SIGNAL_UNKNOWN_CREDENTIAL)
        );
    }

    @SuppressWarnings({"ConstantConditions"})
    @Test
    void create_null_test() {
        assertThatThrownBy(() -> ClientCapability.create(null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void getValue_test() {
        assertThat(ClientCapability.CONDITIONAL_CREATE.getValue()).isEqualTo("conditionalCreate");
    }

    @Test
    void create_invalid_value_test() {
        assertDoesNotThrow(
                () -> ClientCapability.create("unknown")
        );
    }

    @Test
    void deserialize_test() {
        TestDTO dto = jsonMapper.readValue("{\"capability\":\"conditionalCreate\"}", TestDTO.class);
        assertThat(dto.capability).isEqualTo(ClientCapability.CONDITIONAL_CREATE);
    }

    @Test
    void deserialize_test_with_unknown_value() {
        assertDoesNotThrow(
                () -> jsonMapper.readValue("{\"capability\":\"unknown\"}", TestDTO.class)
        );
    }

    @Test
    void deserialize_test_with_invalid_value() {
        assertThatThrownBy(
                () -> jsonMapper.readValue("{\"capability\": -1}", TestDTO.class)
        ).isInstanceOf(MismatchedInputException.class);
    }

    @Test
    void equals_hashCode_test() {
        ClientCapability instanceA = ClientCapability.create("conditionalCreate");
        ClientCapability instanceB = ClientCapability.create("conditionalCreate");
        ClientCapability instanceC = ClientCapability.create("conditionalGet");

        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceA).hasSameHashCodeAs(instanceB),
                () -> assertThat(instanceA).isNotEqualTo(instanceC),
                () -> assertThat(instanceA).isEqualTo(ClientCapability.CONDITIONAL_CREATE),
                () -> assertThat(instanceA).hasSameHashCodeAs(ClientCapability.CONDITIONAL_CREATE)
        );
    }

    @Test
    void toString_test() {
        assertThat(ClientCapability.CONDITIONAL_CREATE.toString()).isEqualTo("conditionalCreate");
        assertThat(ClientCapability.HYBRID_TRANSPORT.toString()).isEqualTo("hybridTransport");
    }

    static class TestDTO {
        @SuppressWarnings("WeakerAccess")
        public ClientCapability capability;
    }
}
