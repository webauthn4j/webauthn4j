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

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class SignatureAlgorithmTest {

    @Test
    void create_test(){
        assertAll(
                () -> assertThat(SignatureAlgorithm.create("SHA256withECDSA")).isEqualTo(SignatureAlgorithm.ES256),
                () -> assertThat(SignatureAlgorithm.create("SHA384withECDSA")).isEqualTo(SignatureAlgorithm.ES384),
                () -> assertThat(SignatureAlgorithm.create("SHA512withECDSA")).isEqualTo(SignatureAlgorithm.ES512),
                () -> assertThat(SignatureAlgorithm.create("SHA1withRSA")).isEqualTo(SignatureAlgorithm.RS1),
                () -> assertThat(SignatureAlgorithm.create("SHA256withRSA")).isEqualTo(SignatureAlgorithm.RS256),
                () -> assertThat(SignatureAlgorithm.create("SHA384withRSA")).isEqualTo(SignatureAlgorithm.RS384),
                () -> assertThat(SignatureAlgorithm.create("SHA512withRSA")).isEqualTo(SignatureAlgorithm.RS512)
        );
    }

    @Test
    void serialize_test(){
        ObjectConverter objectConverter = new ObjectConverter();
        String string = objectConverter.getJsonConverter().writeValueAsString(new TestDto(SignatureAlgorithm.ES256));
        assertThat(string).isEqualTo("{\"alg\":\"SHA256withECDSA\"}");
    }

    @Test
    void override_serialized_value_by_adding_custom_serializer_test(){
        ObjectMapper jsonMapper = new ObjectMapper();
        SimpleModule simpleModule = new SimpleModule();
        simpleModule.addSerializer(new CustomSignatureAlgorithmSerializer());
        jsonMapper.registerModule(simpleModule);
        ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
        ObjectConverter objectConverter = new ObjectConverter(jsonMapper, cborMapper);

        String string = objectConverter.getJsonConverter().writeValueAsString(new TestDto(SignatureAlgorithm.ES256));
        assertThat(string).isEqualTo("{\"alg\":-7}");
    }

    static class CustomSignatureAlgorithmSerializer extends StdSerializer<SignatureAlgorithm> {

        protected CustomSignatureAlgorithmSerializer() {
            super(SignatureAlgorithm.class);
        }

        @Override
        public void serialize(SignatureAlgorithm value, JsonGenerator gen, SerializerProvider provider) throws IOException {
            gen.writeNumber(COSEAlgorithmIdentifier.create(value).getValue());
        }
    }

    static class TestDto{
        private SignatureAlgorithm alg;

        public TestDto(SignatureAlgorithm alg) {
            this.alg = alg;
        }

        public SignatureAlgorithm getAlg() {
            return alg;
        }
    }

}