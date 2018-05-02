package com.webauthn4j.jackson.serializer;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.webauthn4j.client.challenge.Challenge;
import com.webauthn4j.util.Base64UrlUtil;

import java.io.IOException;

public class ChallengeSerializer extends StdSerializer<Challenge> {

    public ChallengeSerializer() {
        super(Challenge.class);
    }

    @Override
    public void serialize(Challenge value, JsonGenerator gen, SerializerProvider provider) throws IOException {
        String challenge = Base64UrlUtil.encodeToString(value.getValue());
        gen.writeString(challenge);
    }
}
