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

package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.jws.JWAIdentifier;
import com.webauthn4j.data.jws.JWSHeader;
import com.webauthn4j.util.Base64Util;
import com.webauthn4j.util.CertificateUtil;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.deser.std.StdDeserializer;

import java.io.IOException;
import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class JWSHeaderDeserializer extends StdDeserializer<JWSHeader> {


    public JWSHeaderDeserializer() {
        super(JWSHeader.class);
    }

    @Override
    public JWSHeader deserialize(@NotNull JsonParser p, @NotNull DeserializationContext ctxt) {
        JsonNode jsonNode = ctxt.readTree(p);
        JWAIdentifier alg = ctxt.readTreeAsValue(jsonNode.get("alg"), JWAIdentifier.class);
        JsonNode x5cNode = jsonNode.get("x5c");
        List<X509Certificate> certificates = new ArrayList<>();
        for (JsonNode node : x5cNode) {
            certificates.add(CertificateUtil.generateX509Certificate(Base64Util.decode(node.asText())));
        }
        CertPath x5c = CertificateUtil.generateCertPath(certificates);
        return new JWSHeader(alg, x5c);
    }
}
