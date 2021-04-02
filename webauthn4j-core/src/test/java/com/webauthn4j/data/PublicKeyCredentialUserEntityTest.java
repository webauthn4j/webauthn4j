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

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class PublicKeyCredentialUserEntityTest {

    @Test
    void constructor_test() {
        PublicKeyCredentialUserEntity userEntity = new PublicKeyCredentialUserEntity(new byte[16], "name", "displayName");
        assertAll(
                () -> assertThat(userEntity.getId()).isEqualTo(new byte[16]),
                () -> assertThat(userEntity.getName()).isEqualTo("name"),
                () -> assertThat(userEntity.getDisplayName()).isEqualTo("displayName")
        );
    }

    @Test
    void equals_hashCode_test() {
        PublicKeyCredentialUserEntity instanceA = new PublicKeyCredentialUserEntity(new byte[16], "name", "displayName");
        PublicKeyCredentialUserEntity instanceB = new PublicKeyCredentialUserEntity(new byte[16], "name", "displayName");

        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceA).hasSameHashCodeAs(instanceB)
        );
    }
}