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

package com.webauthn4j.data.attestation.statement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.test.TestAttestationStatementUtil;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AttestationStatementTest {

    private final ObjectConverter objectConverter = new ObjectConverter();

    @Test
    void serialize_deserialize_with_envelope_class() {
        AttestationStatement attestationStatement = TestAttestationStatementUtil.createBasicPackedAttestationStatement();
        AttestationStatementEnvelope envelope = new AttestationStatementEnvelope(attestationStatement);
        byte[] bytes = objectConverter.getCborConverter().writeValueAsBytes(envelope);
        AttestationStatementEnvelope deserializedEnvelope = objectConverter.getCborConverter().readValue(bytes, AttestationStatementEnvelope.class);
        AttestationStatement deserializedAttestationStatement = deserializedEnvelope.getAttestationStatement();
        assertThat(deserializedAttestationStatement).isEqualTo(attestationStatement);
    }

    static class AttestationStatementEnvelope {

        @JsonProperty("attStmt")
        @JsonTypeInfo(
                use = JsonTypeInfo.Id.NAME,
                include = JsonTypeInfo.As.EXTERNAL_PROPERTY,
                property = "fmt"
        )
        private final AttestationStatement attestationStatement;

        @JsonCreator
        public AttestationStatementEnvelope(@JsonProperty("attStmt") AttestationStatement attestationStatement) {
            this.attestationStatement = attestationStatement;
        }

        @JsonProperty("fmt")
        public String getFormat() {
            return attestationStatement.getFormat();
        }

        public AttestationStatement getAttestationStatement() {
            return attestationStatement;
        }
    }

}