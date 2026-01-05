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
import com.webauthn4j.util.CollectionUtil;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.exc.ValueInstantiationException;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

class PublicKeyCredentialDescriptorTest {

    private final JsonMapper jsonMapper = new ObjectConverter().getJsonMapper();

    @Test
    void getter_test() {
        PublicKeyCredentialDescriptor descriptor = new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, new byte[32], CollectionUtil.unmodifiableSet(AuthenticatorTransport.USB));
        assertAll(
                () -> assertThat(descriptor.getType()).isEqualTo(PublicKeyCredentialType.PUBLIC_KEY),
                () -> assertThat(descriptor.getId()).isEqualTo(new byte[32]),
                () -> assertThat(descriptor.getTransports()).isEqualTo(CollectionUtil.unmodifiableSet(AuthenticatorTransport.USB))
        );
    }

    @Test
    void deserialize_test_with_invalid_value() {
        assertThatThrownBy(
                () -> jsonMapper.readValue("{\"type\": \"public-key\", \"id\": null}", PublicKeyCredentialDescriptor.class)
        ).isInstanceOf(ValueInstantiationException.class);
    }

    @Test
    void equals_hashCode_test() {
        PublicKeyCredentialDescriptor instanceA = new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, new byte[32], CollectionUtil.unmodifiableSet(AuthenticatorTransport.USB));
        PublicKeyCredentialDescriptor instanceB = new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, new byte[32], CollectionUtil.unmodifiableSet(AuthenticatorTransport.USB));

        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceA).hasSameHashCodeAs(instanceB)
        );
    }
}