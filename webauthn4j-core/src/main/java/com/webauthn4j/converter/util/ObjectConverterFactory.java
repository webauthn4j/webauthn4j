package com.webauthn4j.converter.util;

public final class ObjectConverterFactory {

    private static final CborConverter cborConverter = new CborConverter();
    private static final JsonConverter jsonConverter = new JsonConverter();

    private ObjectConverterFactory() {
    }

    public static CborConverter getCborConverter() {
        return cborConverter;
    }

    public static JsonConverter getJsonConverter() {
        return jsonConverter;
    }
}
