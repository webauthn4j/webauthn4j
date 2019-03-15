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
package com.webauthn4j.metadata.data.toc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.webauthn4j.converter.util.ObjectConverterFactory;
import org.junit.jupiter.api.Test;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.JsonConverter;

class AuthenticatorStatusTest {

    JsonConverter jsonConverter = ObjectConverterFactory.getJsonConverter(); // new JsonConverter();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(AuthenticatorStatus.create("FIDO_CERTIFIED")).isEqualTo(AuthenticatorStatus.FIDO_CERTIFIED),
                () -> assertThat(AuthenticatorStatus.create("NOT_FIDO_CERTIFIED")).isEqualTo(AuthenticatorStatus.NOT_FIDO_CERTIFIED),
                () -> assertThat(AuthenticatorStatus.create("USER_VERIFICATION_BYPASS")).isEqualTo(AuthenticatorStatus.USER_VERIFICATION_BYPASS),
                () -> assertThat(AuthenticatorStatus.create("ATTESTATION_KEY_COMPROMISE")).isEqualTo(AuthenticatorStatus.ATTESTATION_KEY_COMPROMISE),
                () -> assertThat(AuthenticatorStatus.create("USER_KEY_REMOTE_COMPROMISE")).isEqualTo(AuthenticatorStatus.USER_KEY_REMOTE_COMPROMISE),
                () -> assertThat(AuthenticatorStatus.create("USER_KEY_PHYSICAL_COMPROMISE")).isEqualTo(AuthenticatorStatus.USER_KEY_PHYSICAL_COMPROMISE),
                () -> assertThat(AuthenticatorStatus.create("UPDATE_AVAILABLE")).isEqualTo(AuthenticatorStatus.UPDATE_AVAILABLE),
                () -> assertThat(AuthenticatorStatus.create("REVOKED")).isEqualTo(AuthenticatorStatus.REVOKED),
                () -> assertThat(AuthenticatorStatus.create("SELF_ASSERTION_SUBMITTED")).isEqualTo(AuthenticatorStatus.SELF_ASSERTION_SUBMITTED),
                () -> assertThat(AuthenticatorStatus.create("FIDO_CERTIFIED_L1")).isEqualTo(AuthenticatorStatus.FIDO_CERTIFIED_L1),
                () -> assertThat(AuthenticatorStatus.create("FIDO_CERTIFIED_L1plus")).isEqualTo(AuthenticatorStatus.FIDO_CERTIFIED_L1_PLUS),
                () -> assertThat(AuthenticatorStatus.create("FIDO_CERTIFIED_L2")).isEqualTo(AuthenticatorStatus.FIDO_CERTIFIED_L2),
                () -> assertThat(AuthenticatorStatus.create("FIDO_CERTIFIED_L2plus")).isEqualTo(AuthenticatorStatus.FIDO_CERTIFIED_L2_PLUS),
                () -> assertThat(AuthenticatorStatus.create("FIDO_CERTIFIED_L3")).isEqualTo(AuthenticatorStatus.FIDO_CERTIFIED_L3),
                () -> assertThat(AuthenticatorStatus.create("FIDO_CERTIFIED_L3plus")).isEqualTo(AuthenticatorStatus.FIDO_CERTIFIED_L3_PLUS),
                () -> assertThrows(IllegalArgumentException.class,
                        () -> AuthenticatorStatus.create("FIDO_CERTIFIED_L1PLUS")),
                () -> assertThat(AuthenticatorStatus.create(null)).isNull()
        );
    }

    @Test
    void getValue_test() {
        assertThat(AuthenticatorStatus.FIDO_CERTIFIED.getValue()).isEqualTo("FIDO_CERTIFIED");
    }

    @Test
    void fromString_test() {
        TestDTO dto = jsonConverter.readValue("{\"authenticator_status\":\"REVOKED\"}", TestDTO.class);
        assertThat(dto.authenticator_status).isEqualTo(AuthenticatorStatus.REVOKED);
    }

    @Test
    void fromString_test_with_invalid_value() {
        assertThrows(DataConversionException.class,
                () -> jsonConverter.readValue("{\"authenticator_status\":\"FIDO_CERTIFIED_L2PLUS\"}", TestDTO.class)
        );
    }

    static class TestDTO {
        public AuthenticatorStatus authenticator_status;
    }
}
