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
import org.springframework.util.Base64Utils;

import java.io.IOException;
import java.io.UncheckedIOException;

/**
 * Converter which converts from {@link WebAuthnAttestationObject} to {@link String}
 */
public class WebAuthnAttestationObjectToBase64StringConverter implements Converter<WebAuthnAttestationObject, String> {

    private ObjectMapper objectMapper;

    public WebAuthnAttestationObjectToBase64StringConverter() {
        this.objectMapper = new ObjectMapper(new CBORFactory());
        this.objectMapper.registerModule(new WebAuthnModule());
    }

    @Override
    public String convert(WebAuthnAttestationObject source) {
        try {
            byte[] bytes = objectMapper.writeValueAsBytes(source);
            return Base64Utils.encodeToUrlSafeString(bytes);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
