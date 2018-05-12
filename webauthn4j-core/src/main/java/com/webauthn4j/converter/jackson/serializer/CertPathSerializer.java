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

package com.webauthn4j.converter.jackson.serializer;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.webauthn4j.util.exception.UnexpectedCheckedException;

import java.io.IOException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

/**
 * Jackson Serializer for CertPath
 */
public class CertPathSerializer extends StdSerializer<CertPath> {
    public CertPathSerializer() {
        super(CertPath.class);
    }

    @Override
    public void serialize(CertPath value, JsonGenerator gen, SerializerProvider provider) throws IOException {
        try {
            gen.writeStartArray();
            for (Certificate certificate : value.getCertificates()) {
                gen.writeBinary(certificate.getEncoded());
            }
            gen.writeEndArray();
        } catch (CertificateEncodingException e) {
            throw new UnexpectedCheckedException(e);
        }
    }
}
