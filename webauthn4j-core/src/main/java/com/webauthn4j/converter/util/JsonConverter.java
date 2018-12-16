package com.webauthn4j.converter.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.UncheckedIOException;

/**
 * A utility class for JSON serialization/deserialization
 */
public class JsonConverter {

    private final ObjectMapper jsonMapper;

    public JsonConverter(ObjectMapper jsonMapper){
        this.jsonMapper = jsonMapper;
    }

    @SuppressWarnings("unchecked")
    public <T> T readValue(String src, Class valueType){
        try {
            return (T)jsonMapper.readValue(src, valueType);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public <T> T readValue(String src, TypeReference valueTypeRef) {
        try {
            return jsonMapper.readValue(src, valueTypeRef);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public byte[] writeValueAsBytes(Object value) {
        try {
            return jsonMapper.writeValueAsBytes(value);
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
    }

    public String writeValueAsString(Object value) {
        try {
            return jsonMapper.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
    }

}
