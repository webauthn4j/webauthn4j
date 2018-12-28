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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.response.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.registry.Registry;
import com.webauthn4j.test.TestUtil;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for EC2CredentialPublicKey
 */
public class EC2CredentialPublicKeyTest {

    private ObjectMapper jsonMapper =  new Registry().getJsonMapper();
    private ObjectMapper cborMapper = new Registry().getCborMapper();

    @Test
    public void createFromUncompressedECCKey_test(){
        EC2CredentialPublicKey.createFromUncompressedECCKey(TestUtil.createECCredentialPublicKey().getBytes());
    }

    @Test(expected = IllegalArgumentException.class)
    public void createFromUncompressedECCKey_with_invalid_length_input_test(){
        EC2CredentialPublicKey.createFromUncompressedECCKey(new byte[64]);
    }

    @Test
    public void equals_test() {
        EC2CredentialPublicKey instanceA = TestUtil.createECCredentialPublicKey();
        EC2CredentialPublicKey instanceB = TestUtil.createECCredentialPublicKey();
        assertThat(instanceA).isEqualTo(instanceB);
    }

    @Test
    public void cbor_serialize_deserialize_test() throws Exception {
        EC2CredentialPublicKey original = TestUtil.createECCredentialPublicKey();
        byte[] serialized = cborMapper.writeValueAsBytes(original);
        CredentialPublicKey result = cborMapper.readValue(serialized, CredentialPublicKey.class);
        assertThat(result).isEqualToComparingFieldByFieldRecursively(original);
    }

    @Test
    public void json_serialize_deserialize_test() throws Exception {
        EC2CredentialPublicKey original = TestUtil.createECCredentialPublicKey();
        String serialized = jsonMapper.writeValueAsString(original);
        CredentialPublicKey result = jsonMapper.readValue(serialized, CredentialPublicKey.class);
        assertThat(result).isEqualToComparingFieldByFieldRecursively(original);
    }

    @Test
    public void validate_test(){
        EC2CredentialPublicKey target = TestUtil.createECCredentialPublicKey();
        target.validate();
    }

    @Test(expected = ConstraintViolationException.class)
    public void validate_with_invalid_algorithm_test(){
        EC2CredentialPublicKey original = TestUtil.createECCredentialPublicKey();
        EC2CredentialPublicKey target = new EC2CredentialPublicKey(
                null,
                null,
                null,
                null,
                Curve.SECP256R1,
                original.getX(),
                original.getY()
        );
        target.validate();
    }

    @Test(expected = ConstraintViolationException.class)
    public void validate_with_invalid_curve_test(){
        EC2CredentialPublicKey original = TestUtil.createECCredentialPublicKey();
        EC2CredentialPublicKey target = new EC2CredentialPublicKey(
                null,
                COSEAlgorithmIdentifier.ES256,
                null,
                null,
                null,
                original.getX(),
                original.getY()
        );
        target.validate();
    }


    @Test(expected = ConstraintViolationException.class)
    public void validate_with_invalid_x_test(){
        EC2CredentialPublicKey original = TestUtil.createECCredentialPublicKey();
        EC2CredentialPublicKey target = new EC2CredentialPublicKey(
                null,
                COSEAlgorithmIdentifier.ES256,
                null,
                null,
                Curve.SECP256R1,
                null,
                original.getY()
        );
        target.validate();
    }

    @Test(expected = ConstraintViolationException.class)
    public void validate_with_invalid_y_test(){
        EC2CredentialPublicKey original = TestUtil.createECCredentialPublicKey();
        EC2CredentialPublicKey target = new EC2CredentialPublicKey(
                null,
                COSEAlgorithmIdentifier.ES256,
                null,
                null,
                Curve.SECP256R1,
                original.getX(),
                null
        );
        target.validate();
    }



}
