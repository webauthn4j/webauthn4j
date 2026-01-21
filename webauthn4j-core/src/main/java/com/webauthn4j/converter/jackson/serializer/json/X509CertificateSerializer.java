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

package com.webauthn4j.converter.jackson.serializer.json;

import com.webauthn4j.util.Base64Util;
import com.webauthn4j.util.exception.UnexpectedCheckedException;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ser.std.StdSerializer;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * Jackson Serializer for {@link X509Certificate}
 */
public class X509CertificateSerializer extends StdSerializer<X509Certificate> {

    public X509CertificateSerializer() {
        super(X509Certificate.class);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void serialize(@NotNull X509Certificate value, @NotNull JsonGenerator gen, @NotNull SerializationContext provider) {
        try {
            String str= Base64Util.encodeToString(value.getEncoded());
            gen.writeString(str);
        } catch (CertificateEncodingException e) {
            throw new UnexpectedCheckedException(e);
        }
    }
}
