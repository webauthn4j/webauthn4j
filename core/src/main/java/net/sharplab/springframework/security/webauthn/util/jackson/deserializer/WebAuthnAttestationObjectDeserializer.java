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

package net.sharplab.springframework.security.webauthn.util.jackson.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import net.sharplab.springframework.security.webauthn.attestation.statement.NoneAttestationStatement;
import net.sharplab.springframework.security.webauthn.exception.UnsupportedArgumentException;
import net.sharplab.springframework.security.webauthn.attestation.WebAuthnAttestationObject;
import net.sharplab.springframework.security.webauthn.attestation.authenticator.WebAuthnAuthenticatorData;
import net.sharplab.springframework.security.webauthn.attestation.statement.FIDOU2FAttestationStatement;
import net.sharplab.springframework.security.webauthn.attestation.statement.PackedAttestationStatement;
import net.sharplab.springframework.security.webauthn.attestation.statement.WebAuthnAttestationStatement;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.SpringSecurityMessageSource;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Jackson Deserializer for WebAuthnAttestationObject
 */
public class WebAuthnAttestationObjectDeserializer extends StdDeserializer<WebAuthnAttestationObject> {

    protected transient MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    private Map<String, Class> attestationStatementTypeMap;

    public WebAuthnAttestationObjectDeserializer() {
        super(WebAuthnAttestationObject.class);
        initializeAttestationSatementTypeMap();
    }

    @Override
    public WebAuthnAttestationObject deserialize(JsonParser p, DeserializationContext context) throws IOException {
        ObjectCodec oc = p.getCodec();
        JsonNode node = oc.readTree(p);
        WebAuthnAuthenticatorData webAuthnAuthenticatorData =  oc.treeToValue(node.get("authData"), WebAuthnAuthenticatorData.class);
        String format = node.get("fmt").asText();
        JsonNode attestationStatementNode = node.get("attStmt");
        WebAuthnAttestationStatement attestationStatement;
        Class attestationStatementType = attestationStatementTypeMap.getOrDefault(format, null);
        if(attestationStatementType == null){
            throw new UnsupportedArgumentException(messages.getMessage(
                    "WebAuthnAttestationObjectDeserializer.unsupportedFormat",
                    "Format is not supported"));
        }
        attestationStatement = (WebAuthnAttestationStatement) oc.treeToValue(attestationStatementNode, attestationStatementType);

        WebAuthnAttestationObject attestationObject = new WebAuthnAttestationObject();
        attestationObject.setAuthenticatorData(webAuthnAuthenticatorData);
        attestationObject.setFormat(format);
        attestationObject.setAttestationStatement(attestationStatement);
        return attestationObject;
    }

    //TODO: polish and retrieve data from config
    private void initializeAttestationSatementTypeMap() {
        attestationStatementTypeMap = new HashMap<>();
        attestationStatementTypeMap.put("fido-u2f", FIDOU2FAttestationStatement.class);
        attestationStatementTypeMap.put("packed", PackedAttestationStatement.class);
        attestationStatementTypeMap.put("none", NoneAttestationStatement.class);
    }



}
