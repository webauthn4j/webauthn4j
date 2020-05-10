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

package com.webauthn4j.data.extension.client;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CredentialPropertiesExtensionClientOutputTest {

    @Test
    void test() {
        CredentialPropertiesExtensionClientOutput target = new CredentialPropertiesExtensionClientOutput(new CredentialPropertiesExtensionClientOutput.CredentialPropertiesOutput(true));
        assertThat(target.getIdentifier()).isEqualTo(CredentialPropertiesExtensionClientOutput.ID);
    }


    @Nested
    class CredentialPropertiesOutputTest{
        @Test
        void getter_test(){
            CredentialPropertiesExtensionClientOutput.CredentialPropertiesOutput target = new CredentialPropertiesExtensionClientOutput.CredentialPropertiesOutput(true);
            assertThat(target.getRk()).isTrue();
        }

        @Test
        void equals_hashCode_test(){
            CredentialPropertiesExtensionClientOutput.CredentialPropertiesOutput instanceA = new CredentialPropertiesExtensionClientOutput.CredentialPropertiesOutput(true);
            CredentialPropertiesExtensionClientOutput.CredentialPropertiesOutput instanceB = new CredentialPropertiesExtensionClientOutput.CredentialPropertiesOutput(true);
            assertThat(instanceA).isEqualTo(instanceB);
            assertThat(instanceA).hasSameHashCodeAs(instanceB);
        }

    }

}