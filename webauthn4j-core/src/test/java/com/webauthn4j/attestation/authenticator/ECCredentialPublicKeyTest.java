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
 * Test for ECCredentialPublicKey
 */
public class ECCredentialPublicKeyTest {

    private ObjectMapper jsonMapper = ObjectMapperUtil.createJSONMapper();
    private ObjectMapper cborMapper = ObjectMapperUtil.createCBORMapper();

    @Test
    public void equals_test() {
        ECCredentialPublicKey instanceA = TestUtil.createECCredentialPublicKey();
        ECCredentialPublicKey instanceB = TestUtil.createECCredentialPublicKey();
        assertThat(instanceA).isEqualTo(instanceB);
    }

    @Test
    public void cbor_serialize_deserialize_test() throws Exception {
        ECCredentialPublicKey original = TestUtil.createECCredentialPublicKey();
        byte[] serialized = cborMapper.writeValueAsBytes(original);
        ECCredentialPublicKey result = cborMapper.readValue(serialized, ECCredentialPublicKey.class);
        assertThat(result).isEqualToComparingFieldByFieldRecursively(original);
    }

    @Test
    public void json_serialize_deserialize_test() throws Exception {
        ECCredentialPublicKey original = TestUtil.createECCredentialPublicKey();
        String serialized = jsonMapper.writeValueAsString(original);
        ECCredentialPublicKey result = jsonMapper.readValue(serialized, ECCredentialPublicKey.class);
        assertThat(result).isEqualToComparingFieldByFieldRecursively(original);
    }
}
