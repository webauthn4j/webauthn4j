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


import com.webauthn4j.data.PublicKeyCredentialRpEntity;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class PublicKeyCredentialRpEntityTest {

    @Test
    void constructor_test() {
        PublicKeyCredentialRpEntity rpEntity = new PublicKeyCredentialRpEntity("localhost", "name");
        assertAll(
                () -> assertThat(rpEntity.getId()).isEqualTo("localhost"),
                () -> assertThat(rpEntity.getName()).isEqualTo("name"),
                () -> assertThat(rpEntity.getIcon()).isEqualTo(null)
        );
    }

    @Test
    void single_arg_constructor_test() {
        PublicKeyCredentialRpEntity rpEntity = new PublicKeyCredentialRpEntity("name");
        assertAll(
                () -> assertThat(rpEntity.getId()).isEqualTo(null),
                () -> assertThat(rpEntity.getName()).isEqualTo("name"),
                () -> assertThat(rpEntity.getIcon()).isEqualTo(null)
        );
    }

    @Test
    void getter_test() {
        PublicKeyCredentialRpEntity rpEntity = new PublicKeyCredentialRpEntity("localhost", "name", "icon");
        assertAll(
                () -> assertThat(rpEntity.getId()).isEqualTo("localhost"),
                () -> assertThat(rpEntity.getName()).isEqualTo("name"),
                () -> assertThat(rpEntity.getIcon()).isEqualTo("icon")
        );
    }

    @Test
    void equals_hashCode_test() {
        PublicKeyCredentialRpEntity instanceA = new PublicKeyCredentialRpEntity("localhost", "name", "icon");
        PublicKeyCredentialRpEntity instanceB = new PublicKeyCredentialRpEntity("localhost", "name", "icon");

        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceA).hasSameHashCodeAs(instanceB)
        );
    }
}