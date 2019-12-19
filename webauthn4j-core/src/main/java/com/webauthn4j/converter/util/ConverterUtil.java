/*
 * Copyright 2018 the original author or authors.
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

package com.webauthn4j.converter.util;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.converter.jackson.WebAuthnCBORModule;
import com.webauthn4j.converter.jackson.WebAuthnJSONModule;

class ConverterUtil {

    private ConverterUtil(){}

    /**
     * Returns the {@link ObjectMapper} configured for JSON processing
     *
     * @return the {@link ObjectMapper} configured for JSON processing
     */
    static ObjectMapper initializeJsonMapper(ObjectMapper jsonMapper, JsonConverter jsonConverter, CborConverter cborConverter) {
        jsonMapper.registerModule(new WebAuthnJSONModule(jsonConverter, cborConverter));
        jsonMapper.configure(DeserializationFeature.WRAP_EXCEPTIONS, false);
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        jsonMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        return jsonMapper;
    }

    /**
     * Returns the {@link ObjectMapper} configured for CBOR processing
     *
     * @return the {@link ObjectMapper} configured for CBOR processing
     */
    static ObjectMapper initializeCborMapper(ObjectMapper cborMapper, JsonConverter jsonConverter, CborConverter cborConverter) {
        cborMapper.registerModule(new WebAuthnCBORModule(jsonConverter, cborConverter));
        cborMapper.configure(DeserializationFeature.WRAP_EXCEPTIONS, false);
        cborMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        cborMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        return cborMapper;
    }


}
