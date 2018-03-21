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

package com.webauthn4j.webauthn.converter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.webauthn.attestation.WebAuthnAttestationObject;
import com.webauthn4j.webauthn.util.WebAuthnModule;
import org.springframework.core.convert.converter.Converter;

import java.io.IOException;
import java.io.UncheckedIOException;

/**
 * Converter which converts from Base64{@link String} to {@link WebAuthnAttestationObject}
 */
public class Base64StringToWebAuthnAttestationObjectConverter implements Converter<String, WebAuthnAttestationObject> {

    private ObjectMapper objectMapper;

    public Base64StringToWebAuthnAttestationObjectConverter() {
        objectMapper = new ObjectMapper(new CBORFactory());
        objectMapper.registerModule(new WebAuthnModule());
    }

    @Override
    public WebAuthnAttestationObject convert(String source) {
        byte[] value = java.util.Base64.getUrlDecoder().decode(source);
        try {
            return objectMapper.readValue(value, WebAuthnAttestationObject.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

}
