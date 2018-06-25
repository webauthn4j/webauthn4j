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
import com.webauthn4j.converter.jackson.ObjectMapperUtil;
import com.webauthn4j.extension.client.ClientExtensionOutput;

import java.util.Map;

/**
 * Converter for {@link Map} of {@link String} and {@link ClientExtensionOutput}
 */
public class ClientExtensionOutputsConverter {

    public Map<String, ClientExtensionOutput> convert(String value) {
        if (value == null) {
            return null;
        }
        return ObjectMapperUtil.readJSONValue(value, new TypeReference<Map<String, ClientExtensionOutput>>(){});
    }

    public String convertToString(Map<String, ClientExtensionOutput> value) {
        if (value == null) {
            return null;
        }
        return ObjectMapperUtil.writeValueAsJSONString(value);
    }

}
