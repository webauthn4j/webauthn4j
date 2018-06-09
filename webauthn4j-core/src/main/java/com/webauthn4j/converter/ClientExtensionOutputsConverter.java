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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.converter.jackson.ObjectMapperUtil;
import com.webauthn4j.extension.client.ClientExtensionOutput;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class ClientExtensionOutputsConverter {

    private final ObjectMapper jsonMapper = ObjectMapperUtil.createJSONMapper();

    public Map<String, ClientExtensionOutput> convert(byte[] value) {
        return convert(new String(value, StandardCharsets.UTF_8));
    }

    public Map<String, ClientExtensionOutput> convert(String value) {
        try {
            if (value == null) {
                return null;
            }
            return jsonMapper.readValue(value, new TypeReference<Map<String, ClientExtensionOutput>>() {
            });
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public String convertToString(Map<String, ClientExtensionOutput> value) {
        try {
            if (value == null) {
                return null;
            }
            return jsonMapper.writeValueAsString(value);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public byte[] convertToBytes(Map<String, ClientExtensionOutput> value) {
        try {
            if (value == null) {
                return new byte[0];
            }
            return jsonMapper.writeValueAsBytes(value);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
