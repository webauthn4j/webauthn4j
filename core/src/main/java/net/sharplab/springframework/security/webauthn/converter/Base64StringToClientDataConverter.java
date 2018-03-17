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

package net.sharplab.springframework.security.webauthn.converter;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.sharplab.springframework.security.webauthn.client.ClientData;
import net.sharplab.springframework.security.webauthn.util.jackson.WebAuthnModule;
import org.springframework.core.convert.converter.Converter;
import org.springframework.util.Base64Utils;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

/**
 * Converter which converts from Base64{@link String} to {@link ClientData}
 */
public class Base64StringToClientDataConverter implements Converter<String, ClientData> {

    private ObjectMapper objectMapper;

    public Base64StringToClientDataConverter(){
        objectMapper = new ObjectMapper();
        objectMapper.registerModule(new WebAuthnModule());
    }

    @Override
    public ClientData convert(String source) {
        byte[] jsonBytes = java.util.Base64.getUrlDecoder().decode(source);
        String jsonString = new String(jsonBytes, StandardCharsets.UTF_8);
        try {
            return objectMapper.readValue(jsonString, ClientData.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
