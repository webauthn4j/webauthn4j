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

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PinProtocolVersionTest {

    @Test
    void constants_test() {
        assertThat(PinProtocolVersion.VERSION_1.getValue()).isEqualTo(1);
        assertThat(PinProtocolVersion.VERSION_2.getValue()).isEqualTo(2);
    }

    @Test
    void create_test() {
        PinProtocolVersion version = PinProtocolVersion.create(3);
        assertThat(version.getValue()).isEqualTo(3);
    }

    @Test
    void equals_hashCode_test() {
        PinProtocolVersion instanceA = PinProtocolVersion.create(1);
        PinProtocolVersion instanceB = new PinProtocolVersion(1);
        PinProtocolVersion instanceC = PinProtocolVersion.create(2);

        assertThat(instanceA).isEqualTo(PinProtocolVersion.VERSION_1);
        assertThat(instanceA).isEqualTo(instanceB);
        assertThat(instanceA).hasSameHashCodeAs(instanceB);

        assertThat(instanceA).isNotEqualTo(instanceC);
    }

    @Test
    void toString_test() {
        assertThat(PinProtocolVersion.VERSION_1).hasToString("1");
        assertThat(PinProtocolVersion.VERSION_2).hasToString("2");
    }
}
