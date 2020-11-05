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
import com.webauthn4j.data.jws.JWSHeader;
import com.webauthn4j.util.Base64Util;
import com.webauthn4j.util.exception.UnexpectedCheckedException;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

public class JWSHeaderSerializer extends StdSerializer<JWSHeader> {

    public JWSHeaderSerializer() {
        super(JWSHeader.class);
    }

    @Override
    public void serialize(JWSHeader value, JsonGenerator gen, SerializerProvider provider) throws IOException {
        try {
        gen.writeStartObject();
        gen.writeObjectField("alg", value.getAlg());
        gen.writeFieldName("x5c");
        gen.writeStartArray();
        if(value.getX5c() != null){
            for(Certificate certificate : value.getX5c().getCertificates()){
                gen.writeString(Base64Util.encodeToString(certificate.getEncoded())); // x5c must be Base64, not Base64Url
            }
        }
        gen.writeEndArray();
        } catch (CertificateEncodingException e) {
            throw new UnexpectedCheckedException(e);
        }
    }
}
