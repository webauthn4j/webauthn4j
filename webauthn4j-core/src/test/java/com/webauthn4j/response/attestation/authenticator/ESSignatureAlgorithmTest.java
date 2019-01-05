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

package com.webauthn4j.response.attestation.authenticator;

import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.webauthn4j.response.attestation.statement.COSEAlgorithmIdentifier;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class ESSignatureAlgorithmTest {

    @Test
    public void create_test() throws InvalidFormatException {
        assertThat(COSEAlgorithmIdentifier.create(-7)).isEqualTo(COSEAlgorithmIdentifier.ES256);
        assertThat(COSEAlgorithmIdentifier.create(-35)).isEqualTo(COSEAlgorithmIdentifier.ES384);
        assertThat(COSEAlgorithmIdentifier.create(-36)).isEqualTo(COSEAlgorithmIdentifier.ES512);
    }

    @Test
    public void create_with_invalid_value_test() {
        //noinspection ResultOfMethodCallIgnored
        assertThatThrownBy(() -> COSEAlgorithmIdentifier.create(0)).isInstanceOf(InvalidFormatException.class);
    }

    @Test
    public void equals_test() {
        assertThat(COSEAlgorithmIdentifier.ES256).isEqualTo(COSEAlgorithmIdentifier.ES256);
        assertThat(COSEAlgorithmIdentifier.ES384).isNotEqualTo(COSEAlgorithmIdentifier.ES512);
    }


}
