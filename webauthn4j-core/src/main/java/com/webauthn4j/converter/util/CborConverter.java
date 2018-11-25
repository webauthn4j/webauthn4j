package com.webauthn4j.converter.util;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;

/**
 * A utility class for CBOR serialization/deserialization
 */
public class CborConverter {

    private final ObjectMapper cborMapper;

    public CborConverter(ObjectMapper cborMapper) {
        this.cborMapper = cborMapper;
    }

    @SuppressWarnings("unchecked")
    public <T> T readValue(byte[] src, Class valueType){
        try {
            return (T)cborMapper.readValue(src, valueType);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @SuppressWarnings("unchecked")
    public <T> T readValue(InputStream src, Class valueType){
        try {
            return (T)cborMapper.readValue(src, valueType);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public <T> T readValue(byte[] src, TypeReference valueTypeRef) {
        try {
            return cborMapper.readValue(src, valueTypeRef);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public JsonNode readTree(byte[] bytes){
        try {
            return cborMapper.readTree(bytes);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public byte[] writeValueAsBytes(Object value){
        try {
            return cborMapper.writeValueAsBytes(value);
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
    }

}
