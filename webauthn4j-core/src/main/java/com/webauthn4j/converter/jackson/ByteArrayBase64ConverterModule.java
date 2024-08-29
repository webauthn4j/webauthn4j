package com.webauthn4j.converter.jackson;

import com.fasterxml.jackson.databind.module.SimpleModule;
import com.webauthn4j.converter.jackson.deserializer.json.ByteArrayBase64Deserializer;
import com.webauthn4j.converter.jackson.serializer.json.ByteArrayBase64Serializer;

public class ByteArrayBase64ConverterModule extends SimpleModule {

    public ByteArrayBase64ConverterModule(){
        this.addDeserializer(byte[].class, new ByteArrayBase64Deserializer());
        this.addSerializer(new ByteArrayBase64Serializer());
    }
}
