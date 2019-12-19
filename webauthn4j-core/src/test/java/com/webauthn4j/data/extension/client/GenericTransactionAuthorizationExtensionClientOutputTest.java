/*
 * Copyright 2018 the original author or authors.
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

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class GenericTransactionAuthorizationExtensionClientOutputTest {

    @Test
    void test() {
        GenericTransactionAuthorizationExtensionClientOutput target
                = new GenericTransactionAuthorizationExtensionClientOutput(new GenericTransactionAuthorizationExtensionClientOutput.TxAuthnGenericArg());
        assertThat(target.getIdentifier()).isEqualTo(GenericTransactionAuthorizationExtensionClientOutput.ID);
    }

    @Test
    void TxAuthnGenericArg_getter_setter_test() {
        GenericTransactionAuthorizationExtensionClientOutput.TxAuthnGenericArg target
                = new GenericTransactionAuthorizationExtensionClientOutput.TxAuthnGenericArg("type", new byte[32]);
        assertAll(
                () -> assertThat(target.getContentType()).isEqualTo("type"),
                () -> assertThat(target.getContent()).isEqualTo(new byte[32])
        );
    }

    @Test
    void TxAuthnGenericArg_equals_hashCode_test() {
        GenericTransactionAuthorizationExtensionClientOutput.TxAuthnGenericArg instanceA = new GenericTransactionAuthorizationExtensionClientOutput.TxAuthnGenericArg();
        GenericTransactionAuthorizationExtensionClientOutput.TxAuthnGenericArg instanceB = new GenericTransactionAuthorizationExtensionClientOutput.TxAuthnGenericArg();
        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceA).hasSameHashCodeAs(instanceB)
        );
    }
}
