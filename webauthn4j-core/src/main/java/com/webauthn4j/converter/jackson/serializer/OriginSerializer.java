package com.webauthn4j.converter.jackson.serializer;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.webauthn4j.client.Origin;

import java.io.IOException;

public class OriginSerializer extends StdSerializer<Origin> {
    public OriginSerializer() {
        super(Origin.class);
    }

    @Override
    public void serialize(Origin value, JsonGenerator gen, SerializerProvider provider) throws IOException {
        gen.writeString(value.toString());
    }
}
