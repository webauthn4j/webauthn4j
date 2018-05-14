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

package com.webauthn4j.attestation.authenticator;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.converter.jackson.ObjectMapperUtil;
import com.webauthn4j.test.TestUtil;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for RSACredentialPublicKey
 */
public class RSACredentialPublicKeyTest {

    private ObjectMapper jsonMapper = ObjectMapperUtil.createJSONMapper();
    private ObjectMapper cborMapper = ObjectMapperUtil.createCBORMapper();

    @Test
    public void equals_test() {
        RSACredentialPublicKey instanceA = TestUtil.createRSCredentialPublicKey();
        RSACredentialPublicKey instanceB = TestUtil.createRSCredentialPublicKey();
        assertThat(instanceA).isEqualTo(instanceB);
    }

    @Test
    public void cbor_serialize_deserialize_test() throws Exception {
        RSACredentialPublicKey original = TestUtil.createRSCredentialPublicKey();
        byte[] serialized = cborMapper.writeValueAsBytes(original);
        RSACredentialPublicKey result = cborMapper.readValue(serialized, RSACredentialPublicKey.class);
        assertThat(result).isEqualToComparingFieldByFieldRecursively(original);
    }

    @Test
    public void json_serialize_deserialize_test() throws Exception {
        RSACredentialPublicKey original = TestUtil.createRSCredentialPublicKey();
        String serialized = jsonMapper.writeValueAsString(original);
        RSACredentialPublicKey result = jsonMapper.readValue(serialized, RSACredentialPublicKey.class);
        assertThat(result).isEqualToComparingFieldByFieldRecursively(original);
    }
}
