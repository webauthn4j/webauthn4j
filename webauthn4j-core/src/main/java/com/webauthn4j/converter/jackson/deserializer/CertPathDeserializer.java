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

package com.webauthn4j.converter.jackson.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.webauthn4j.util.CertificateUtil;

import java.io.IOException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Jackson Deserializer for CertPath
 */
public class CertPathDeserializer extends StdDeserializer<CertPath> {

    public CertPathDeserializer() {
        super(CertPath.class);
    }

    @Override
    public CertPath deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {

        ObjectCodec oc = p.getCodec();
        ArrayNode node = oc.readTree(p);
        List<Certificate> list = new ArrayList<>();
        for (JsonNode item : node) {
            X509Certificate certificate = oc.treeToValue(item, X509Certificate.class);
            list.add(certificate);
        }
        return CertificateUtil.generateCertPath(list);
    }
}
