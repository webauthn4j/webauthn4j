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

package com.webauthn4j.converter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.converter.jackson.ObjectMapperUtil;
import com.webauthn4j.util.Base64UrlUtil;

import java.io.IOException;
import java.io.UncheckedIOException;

public class AttestationObjectConverter {

    private ObjectMapper objectMapper;

    public AttestationObject convert(String source) {
        byte[] value = Base64UrlUtil.decode(source);
        return convert(value);
    }

    public AttestationObject convert(byte[] source) {
        try {
            return getCborMapper().readValue(source, AttestationObject.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public byte[] convertToBytes(AttestationObject source) {
        try {
            return getCborMapper().writeValueAsBytes(source);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public String convertToString(AttestationObject source) {
        byte[] bytes = convertToBytes(source);
        return Base64UrlUtil.encodeToString(bytes);
    }

    private ObjectMapper getCborMapper() {
        if (this.objectMapper == null) {
            this.objectMapper = ObjectMapperUtil.createCBORMapper();
        }
        return this.objectMapper;
    }

}
