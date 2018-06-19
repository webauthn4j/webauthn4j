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

package com.webauthn4j.converter.jackson;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;

/**
 * A utility class for {@link ObjectMapper} creation
 */
public class ObjectMapperUtil {

    private static ObjectMapper jsonMapper = createWebAuthnClassesAwareJSONMapper();
    private static ObjectMapper cborMapper = createWebAuthnClassesAwareCBORMapper();

    private ObjectMapperUtil() {
    }

    /**
     * Creates WebAuthn classes aware ObjectMapper for JSON mapping
     * @return objectMapper
     */
    public static ObjectMapper createWebAuthnClassesAwareJSONMapper() {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new WebAuthnModule());
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        return objectMapper;
    }

    /**
     * Creates WebAuthn classes aware ObjectMapper for CBOR mapping
     * @return objectMapper
     */
    public static ObjectMapper createWebAuthnClassesAwareCBORMapper() {
        ObjectMapper objectMapper = new ObjectMapper(new CBORFactory());
        objectMapper.registerModule(new WebAuthnModule());
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        return objectMapper;
    }

    @SuppressWarnings("unchecked")
    public static <T> T readJSONValue(String src, Class valueType){
        try {
            return (T)jsonMapper.readValue(src, valueType);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @SuppressWarnings("unchecked")
    public static <T> T readCBORValue(byte[] src, Class valueType){
        try {
            return (T)cborMapper.readValue(src, valueType);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @SuppressWarnings("unchecked")
    public static <T> T readCBORValue(InputStream src, Class valueType){
        try {
            return (T)cborMapper.readValue(src, valueType);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static <T> T readJSONValue(byte[] src, TypeReference valueTypeRef) {
        try {
            return jsonMapper.readValue(src, valueTypeRef);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static <T> T readJSONValue(String src, TypeReference valueTypeRef) {
        try {
            return jsonMapper.readValue(src, valueTypeRef);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static <T> T readCBORValue(byte[] src, TypeReference valueTypeRef) {
        try {
            return cborMapper.readValue(src, valueTypeRef);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static byte[] writeValueAsJSONBytes(Object value) {
        try {
            return jsonMapper.writeValueAsBytes(value);
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static byte[] writeValueAsCBORBytes(Object value){
        try {
            return cborMapper.writeValueAsBytes(value);
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static String writeValueAsJSONString(Object value) {
        try {
            return jsonMapper.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
    }
}
