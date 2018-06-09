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
import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.converter.jackson.ObjectMapperUtil;
import com.webauthn4j.util.Base64UrlUtil;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

public class CollectedClientDataConverter {

    private final ObjectMapper jsonMapper;

    public CollectedClientDataConverter() {
        jsonMapper = ObjectMapperUtil.createJSONMapper();
    }

    public CollectedClientData convert(String base64UrlString) {
        byte[] bytes = Base64UrlUtil.decode(base64UrlString);
        return convert(bytes);
    }

    public CollectedClientData convert(byte[] source) {
        String jsonString = new String(source, StandardCharsets.UTF_8);
        try {
            return jsonMapper.readValue(jsonString, CollectedClientData.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public byte[] convertToBytes(CollectedClientData source) {
        try {
            return jsonMapper.writeValueAsBytes(source);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public String convertToString(CollectedClientData source) {
        byte[] bytes = convertToBytes(source);
        return Base64UrlUtil.encodeToString(bytes);
    }

}
