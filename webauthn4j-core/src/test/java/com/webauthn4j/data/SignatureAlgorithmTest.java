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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.util.SignatureUtil;
import org.junit.jupiter.api.Test;
import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.exc.InvalidFormatException;
import tools.jackson.databind.exc.MismatchedInputException;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.dataformat.cbor.CBORMapper;
import tools.jackson.databind.module.SimpleModule;
import tools.jackson.databind.ser.std.StdSerializer;

import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertAll;

class SignatureAlgorithmTest {

    private final JsonMapper jsonMapper = new ObjectConverter().getJsonMapper();

    @Deprecated
    @Test
    void create_test() {
        assertAll(
                () -> assertThat(SignatureAlgorithm.create("SHA256withECDSA")).isEqualTo(SignatureAlgorithm.ES256),
                () -> assertThat(SignatureAlgorithm.create("SHA384withECDSA")).isEqualTo(SignatureAlgorithm.ES384),
                () -> assertThat(SignatureAlgorithm.create("SHA512withECDSA")).isEqualTo(SignatureAlgorithm.ES512),
                () -> assertThat(SignatureAlgorithm.create("SHA1withRSA")).isEqualTo(SignatureAlgorithm.RS1),
                () -> assertThat(SignatureAlgorithm.create("SHA256withRSA")).isEqualTo(SignatureAlgorithm.RS256),
                () -> assertThat(SignatureAlgorithm.create("SHA384withRSA")).isEqualTo(SignatureAlgorithm.RS384),
                () -> assertThat(SignatureAlgorithm.create("SHA512withRSA")).isEqualTo(SignatureAlgorithm.RS512),
                () -> assertThat(SignatureAlgorithm.create("ed25519")).isEqualTo(SignatureAlgorithm.Ed25519),
                () -> assertThat(SignatureAlgorithm.create("ed448")).isEqualTo(SignatureAlgorithm.Ed448),
                () -> assertThat(SignatureAlgorithm.create("ML-DSA-44")).isEqualTo(SignatureAlgorithm.ML_DSA_44),
                () -> assertThat(SignatureAlgorithm.create("ML-DSA-65")).isEqualTo(SignatureAlgorithm.ML_DSA_65),
                () -> assertThat(SignatureAlgorithm.create("ML-DSA-87")).isEqualTo(SignatureAlgorithm.ML_DSA_87),
                () -> assertThatThrownBy(()->SignatureAlgorithm.create("invalid")).isInstanceOf(IllegalArgumentException.class)
        );
    }

    @Test
    void deserialize_test() {
        assertAll(
                () -> assertThat(jsonMapper.readValue("{\"alg\":\"SHA256withECDSA\"}", TestDto.class).getAlg()).isEqualTo(SignatureAlgorithm.ES256),
                () -> assertThat(jsonMapper.readValue("{\"alg\":\"SHA384withECDSA\"}", TestDto.class).getAlg()).isEqualTo(SignatureAlgorithm.ES384),
                () -> assertThat(jsonMapper.readValue("{\"alg\":\"SHA512withECDSA\"}", TestDto.class).getAlg()).isEqualTo(SignatureAlgorithm.ES512),
                () -> assertThat(jsonMapper.readValue("{\"alg\":\"SHA1withRSA\"}", TestDto.class).getAlg()).isEqualTo(SignatureAlgorithm.RS1),
                () -> assertThat(jsonMapper.readValue("{\"alg\":\"SHA256withRSA\"}", TestDto.class).getAlg()).isEqualTo(SignatureAlgorithm.RS256),
                () -> assertThat(jsonMapper.readValue("{\"alg\":\"SHA384withRSA\"}", TestDto.class).getAlg()).isEqualTo(SignatureAlgorithm.RS384),
                () -> assertThat(jsonMapper.readValue("{\"alg\":\"SHA512withRSA\"}", TestDto.class).getAlg()).isEqualTo(SignatureAlgorithm.RS512),
                () -> assertThat(jsonMapper.readValue("{\"alg\":\"ed25519\"}", TestDto.class).getAlg()).isEqualTo(SignatureAlgorithm.Ed25519),
                () -> assertThat(jsonMapper.readValue("{\"alg\":\"ed448\"}", TestDto.class).getAlg()).isEqualTo(SignatureAlgorithm.Ed448),
                () -> assertThat(jsonMapper.readValue("{\"alg\":\"SHA256withRSA/PSS\"}", TestDto.class).getAlg()).isEqualTo(SignatureAlgorithm.PS256),
                () -> assertThat(jsonMapper.readValue("{\"alg\":\"SHA384withRSA/PSS\"}", TestDto.class).getAlg()).isEqualTo(SignatureAlgorithm.PS384),
                () -> assertThat(jsonMapper.readValue("{\"alg\":\"SHA512withRSA/PSS\"}", TestDto.class).getAlg()).isEqualTo(SignatureAlgorithm.PS512),
                () -> assertThat(jsonMapper.readValue("{\"alg\":\"ML-DSA-44\"}", TestDto.class).getAlg()).isEqualTo(SignatureAlgorithm.ML_DSA_44),
                () -> assertThat(jsonMapper.readValue("{\"alg\":\"ML-DSA-65\"}", TestDto.class).getAlg()).isEqualTo(SignatureAlgorithm.ML_DSA_65),
                () -> assertThat(jsonMapper.readValue("{\"alg\":\"ML-DSA-87\"}", TestDto.class).getAlg()).isEqualTo(SignatureAlgorithm.ML_DSA_87),
                () -> assertThatThrownBy(() -> jsonMapper.readValue("{\"alg\":\"invalid\"}", TestDto.class)).isInstanceOf(InvalidFormatException.class)
        );
    }

    @Test
    void toString_test() {
        assertAll(
                () -> assertThat(SignatureAlgorithm.ES256).hasToString("ES256"),
                () -> assertThat(SignatureAlgorithm.ES384).hasToString("ES384"),
                () -> assertThat(SignatureAlgorithm.ES512).hasToString("ES512"),
                () -> assertThat(SignatureAlgorithm.RS1).hasToString("RS1"),
                () -> assertThat(SignatureAlgorithm.RS256).hasToString("RS256"),
                () -> assertThat(SignatureAlgorithm.RS384).hasToString("RS384"),
                () -> assertThat(SignatureAlgorithm.RS512).hasToString("RS512"),
                () -> assertThat(SignatureAlgorithm.Ed25519).hasToString("Ed25519"),
                () -> assertThat(SignatureAlgorithm.Ed448).hasToString("Ed448"),
                () -> assertThat(SignatureAlgorithm.PS256).hasToString("PS256"),
                () -> assertThat(SignatureAlgorithm.PS384).hasToString("PS384"),
                () -> assertThat(SignatureAlgorithm.PS512).hasToString("PS512"),
                () -> assertThat(SignatureAlgorithm.ML_DSA_44).hasToString("ML-DSA-44"),
                () -> assertThat(SignatureAlgorithm.ML_DSA_65).hasToString("ML-DSA-65"),
                () -> assertThat(SignatureAlgorithm.ML_DSA_87).hasToString("ML-DSA-87")
        );
    }


    @Test
    void ed25519_test(){
        assertThatCode(()->{
            SignatureUtil.createSignature(SignatureAlgorithm.Ed25519);
        }).doesNotThrowAnyException();
    }

    @Test
    void serialize_test() {
        String string = jsonMapper.writeValueAsString(new TestDto(SignatureAlgorithm.ES256));
        assertThat(string).isEqualTo("{\"alg\":\"SHA256withECDSA\"}");
    }

    @Test
    void deserialize_test_with_invalid_value() {
        assertThatThrownBy(
                () -> jsonMapper.readValue("{\"alg\": -1}", SignatureAlgorithmTest.TestDto.class)
        ).isInstanceOf(MismatchedInputException.class);
    }

    @Test
    void override_serialized_value_by_adding_custom_serializer_test() {
        SimpleModule simpleModule = new SimpleModule();
        simpleModule.addSerializer(new CustomSignatureAlgorithmSerializer());
        JsonMapper customizedJsonMapper = jsonMapper.rebuild()
                .addModule(simpleModule)
                .build();
        ObjectConverter objectConverter = new ObjectConverter(customizedJsonMapper, new CBORMapper());

        String string = objectConverter.getJsonMapper().writeValueAsString(new TestDto(SignatureAlgorithm.ES256));
        assertThat(string).isEqualTo("{\"alg\":-7}");
    }

    static class CustomSignatureAlgorithmSerializer extends StdSerializer<SignatureAlgorithm> {

        protected CustomSignatureAlgorithmSerializer() {
            super(SignatureAlgorithm.class);
        }

        @Override
        public void serialize(SignatureAlgorithm value, JsonGenerator gen, SerializationContext provider) throws JacksonException {
            gen.writeNumber(COSEAlgorithmIdentifier.create(value).getValue());
        }
    }

    static class TestDto {
        private final SignatureAlgorithm alg;

        @JsonCreator
        public TestDto(@JsonProperty("alg") SignatureAlgorithm alg) {
            this.alg = alg;
        }

        public SignatureAlgorithm getAlg() {
            return alg;
        }
    }

}