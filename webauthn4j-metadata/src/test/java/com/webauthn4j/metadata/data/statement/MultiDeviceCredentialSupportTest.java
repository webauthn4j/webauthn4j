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

package com.webauthn4j.metadata.data.statement;

import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;

class MultiDeviceCredentialSupportTest {

    private final JsonMapper jsonMapper = new ObjectConverter().getJsonMapper();

    @Test
    void constants_test() {
        assertThat(MultiDeviceCredentialSupport.UNSUPPORTED.getValue()).isEqualTo("unsupported");
        assertThat(MultiDeviceCredentialSupport.EXPLICIT.getValue()).isEqualTo("explicit");
        assertThat(MultiDeviceCredentialSupport.IMPLICIT.getValue()).isEqualTo("implicit");
    }

    @Test
    void equals_hashCode_test() {
        MultiDeviceCredentialSupport a = new MultiDeviceCredentialSupport("explicit");
        MultiDeviceCredentialSupport b = new MultiDeviceCredentialSupport("explicit");
        MultiDeviceCredentialSupport c = new MultiDeviceCredentialSupport("implicit");
        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
        assertThat(a).isEqualTo(MultiDeviceCredentialSupport.EXPLICIT);
        assertThat(a).isNotEqualTo(c);
        assertThat(a).isNotEqualTo(null);
        assertThat(a).isNotEqualTo("explicit");
    }

    @Test
    void toString_test() {
        assertThat(MultiDeviceCredentialSupport.EXPLICIT.toString()).isEqualTo("explicit");
    }

    @Test
    void json_roundTrip_test() {
        String json = jsonMapper.writeValueAsString(MultiDeviceCredentialSupport.EXPLICIT);
        MultiDeviceCredentialSupport deserialized = jsonMapper.readValue(json, MultiDeviceCredentialSupport.class);
        assertThat(deserialized).isEqualTo(MultiDeviceCredentialSupport.EXPLICIT);
    }

    @Test
    void unknown_value_test() {
        MultiDeviceCredentialSupport unknown = new MultiDeviceCredentialSupport("future-value");
        assertThat(unknown.getValue()).isEqualTo("future-value");
        assertThat(unknown).isNotEqualTo(MultiDeviceCredentialSupport.UNSUPPORTED);
    }
}
