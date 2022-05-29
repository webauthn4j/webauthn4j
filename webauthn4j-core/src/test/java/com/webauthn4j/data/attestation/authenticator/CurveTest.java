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

package com.webauthn4j.data.attestation.authenticator;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.util.ECUtil;
import org.junit.jupiter.api.Test;

import java.security.spec.NamedParameterSpec;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CurveTest {

    private final JsonConverter jsonConverter = new ObjectConverter().getJsonConverter();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(Curve.create(1)).isEqualTo(Curve.SECP256R1),
                () -> assertThat(Curve.create(2)).isEqualTo(Curve.SECP384R1),
                () -> assertThat(Curve.create(3)).isEqualTo(Curve.SECP521R1),
                () -> assertThat(Curve.create(6)).isEqualTo(Curve.ED25519),
                () -> assertThatThrownBy(() -> Curve.create(4)).isInstanceOf(IllegalArgumentException.class)
        );
    }

    @Test
    void deserialize_with_invalid_value_test() {
        assertThrows(DataConversionException.class,
                () -> jsonConverter.readValue("{\"value\": -1}", CurveDto.class)
        );
    }

    @SuppressWarnings("Since15")
    @Test
    void getParameterSpec_test() {
        assertAll(
                () -> assertThat(Curve.SECP256R1.getParameterSpec()).isEqualTo(ECUtil.P_256_SPEC),
                () -> assertThat(Curve.SECP384R1.getParameterSpec()).isEqualTo(ECUtil.P_384_SPEC),
                () -> assertThat(Curve.SECP521R1.getParameterSpec()).isEqualTo(ECUtil.P_521_SPEC),
                () -> assertThat(((NamedParameterSpec)Curve.ED25519.getParameterSpec()).getName()).isEqualTo(NamedParameterSpec.ED25519.getName())
        );
    }

    @Test
    void toString_test() {
        assertAll(
                () -> assertThat(Curve.SECP256R1).hasToString("SECP256R1"),
                () -> assertThat(Curve.SECP384R1).hasToString("SECP384R1"),
                () -> assertThat(Curve.SECP521R1).hasToString("SECP521R1"),
                () -> assertThat(Curve.ED25519).hasToString("ED25519")
        );
    }

    static class CurveDto {
        private Curve value;

        public Curve getValue() {
            return value;
        }

        public void setValue(Curve value) {
            this.value = value;
        }
    }
}