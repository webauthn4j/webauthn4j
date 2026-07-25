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

package com.webauthn4j.converter.jackson.serializer.cbor;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AKPCOSEKey;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.condition.JRE;
import tools.jackson.databind.JsonNode;
import tools.jackson.dataformat.cbor.CBORMapper;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.assertj.core.api.Assertions.assertThat;

@EnabledForJreRange(min = JRE.JAVA_24)
class AKPCOSEKeySerializerTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final CBORMapper cborMapper = objectConverter.getCborMapper();

    @Test
    void serialized_cbor_should_contain_kty_field() throws Exception {
        // Given
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65");
        KeyPair keyPair = kpg.generateKeyPair();
        AKPCOSEKey coseKey = AKPCOSEKey.create(keyPair.getPublic(), COSEAlgorithmIdentifier.ML_DSA_65);

        // When
        byte[] cbor = cborMapper.writeValueAsBytes(coseKey);
        JsonNode root = cborMapper.readTree(cbor);

        // Then - CBOR integer key 1 (kty) must be present as a numeric value 7 (AKP).
        // Without a custom AKPCOSEKeySerializer, Jackson falls back to annotation-based
        // serialization which outputs kty as a string "7" instead of the integer 7.
        JsonNode ktyNode = root.get("1");
        assertThat(ktyNode)
                .as("CBOR map must contain integer key 1 (kty)")
                .isNotNull();
        assertThat(ktyNode.isNumber())
                .as("kty value must be serialized as a CBOR integer, not a string")
                .isTrue();
        assertThat(ktyNode.intValue()).isEqualTo(7);
    }

    @Test
    void serialized_cbor_should_contain_alg_field() throws Exception {
        // Given
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65");
        KeyPair keyPair = kpg.generateKeyPair();
        AKPCOSEKey coseKey = AKPCOSEKey.create(keyPair.getPublic(), COSEAlgorithmIdentifier.ML_DSA_65);

        // When
        byte[] cbor = cborMapper.writeValueAsBytes(coseKey);
        JsonNode root = cborMapper.readTree(cbor);

        // Then - CBOR integer key "3" (alg) must be present with value -49 (ML-DSA-65)
        JsonNode algNode = root.get("3");
        assertThat(algNode)
                .as("CBOR map must contain integer key 3 (alg)")
                .isNotNull();
        assertThat(algNode.intValue()).isEqualTo(-49);
    }

    @Test
    void serialized_cbor_should_contain_pub_field() throws Exception {
        // Given
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65");
        KeyPair keyPair = kpg.generateKeyPair();
        AKPCOSEKey coseKey = AKPCOSEKey.create(keyPair.getPublic(), COSEAlgorithmIdentifier.ML_DSA_65);

        // When
        byte[] cbor = cborMapper.writeValueAsBytes(coseKey);
        JsonNode root = cborMapper.readTree(cbor);

        // Then - CBOR integer key "-1" (pub) must be present
        JsonNode pubNode = root.get("-1");
        assertThat(pubNode)
                .as("CBOR map must contain integer key -1 (pub)")
                .isNotNull();
        assertThat(pubNode.binaryValue()).isEqualTo(coseKey.getPub());
    }
}
