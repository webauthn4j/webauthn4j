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

package com.webauthn4j.converter.jackson.deserializer.cbor;

import com.webauthn4j.util.CertificateUtil;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.core.ObjectReadContext;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.deser.std.StdDeserializer;
import tools.jackson.databind.node.ArrayNode;

import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Jackson Deserializer for {@link CertPath}
 */
public class CertPathDeserializer extends StdDeserializer<CertPath> {

    public CertPathDeserializer() {
        super(CertPath.class);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public @NotNull CertPath deserialize(@NotNull JsonParser p, @NotNull DeserializationContext ctxt) {

        ObjectReadContext objectReadContext = p.objectReadContext();
        ArrayNode node = objectReadContext.readTree(p);
        List<Certificate> list = new ArrayList<>();
        for (JsonNode item : node) {
            X509Certificate certificate = ctxt.readTreeAsValue(item, X509Certificate.class);
            list.add(certificate);
        }
        return CertificateUtil.generateCertPath(list);
    }
}
