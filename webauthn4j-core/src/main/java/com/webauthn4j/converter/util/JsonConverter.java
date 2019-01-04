package com.webauthn4j.converter.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.MismatchedInputException;
import com.webauthn4j.converter.exception.DataConversionException;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;

/**
 * A utility class for JSON serialization/deserialization
 */
public class JsonConverter {

    private static final String INPUT_MISMATCH_ERROR_MESSAGE = "Input data does not match expected form";

    private final ObjectMapper jsonMapper;

    public JsonConverter(ObjectMapper jsonMapper){
        this.jsonMapper = jsonMapper;
    }

    @SuppressWarnings("unchecked")
    public <T> T readValue(String src, Class valueType){
        try {
            return (T)jsonMapper.readValue(src, valueType);
        }
        catch (MismatchedInputException e){
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        }
        catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @SuppressWarnings("unchecked")
    public <T> T readValue(InputStream src, Class valueType){
        try {
            return (T)jsonMapper.readValue(src, valueType);
        }
        catch (MismatchedInputException e){
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        }
        catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public <T> T readValue(String src, TypeReference valueTypeRef) {
        try {
            return jsonMapper.readValue(src, valueTypeRef);
        }
        catch (MismatchedInputException e){
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        }
        catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public byte[] writeValueAsBytes(Object value) {
        try {
            return jsonMapper.writeValueAsBytes(value);
        }
        catch (MismatchedInputException e){
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        }
        catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
    }

    public String writeValueAsString(Object value) {
        try {
            return jsonMapper.writeValueAsString(value);
        }
        catch (MismatchedInputException e){
            throw new DataConversionException("Input data does not match expected form", e);
        }
        catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
    }

}
