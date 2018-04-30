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

package com.webauthn4j.jackson.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.attestation.statement.FIDOU2FAttestationStatement;
import com.webauthn4j.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.attestation.statement.AttestationStatement;
import com.webauthn4j.validator.exception.UnsupportedAttestationFormatException;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Jackson Deserializer for AttestationObject
 */
public class AttestationObjectDeserializer extends StdDeserializer<AttestationObject> {

    private Map<String, Class> attestationStatementTypeMap;

    public AttestationObjectDeserializer() {
        super(AttestationObject.class);
        initializeAttestationStatementTypeMap();
    }

    @Override
    public AttestationObject deserialize(JsonParser p, DeserializationContext context) throws IOException {
        ObjectCodec oc = p.getCodec();
        JsonNode node = oc.readTree(p);
        AuthenticatorData authenticatorData = oc.treeToValue(node.get("authData"), AuthenticatorData.class);
        String format = node.get("fmt").asText();
        JsonNode attestationStatementNode = node.get("attStmt");
        AttestationStatement attestationStatement;
        Class attestationStatementType = attestationStatementTypeMap.getOrDefault(format, null);
        if (attestationStatementType == null) {
            throw new UnsupportedAttestationFormatException("Format is not supported");
        }
        attestationStatement = (AttestationStatement) oc.treeToValue(attestationStatementNode, attestationStatementType);

        return new AttestationObject(authenticatorData, attestationStatement);
    }

    //TODO: polish and retrieve data from config
    private void initializeAttestationStatementTypeMap() {
        attestationStatementTypeMap = new HashMap<>();
        attestationStatementTypeMap.put("fido-u2f", FIDOU2FAttestationStatement.class);
        attestationStatementTypeMap.put("packed", PackedAttestationStatement.class);
        attestationStatementTypeMap.put("none", NoneAttestationStatement.class);
    }


}
