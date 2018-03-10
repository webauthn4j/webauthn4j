package net.sharplab.springframework.security.webauthn.util.jackson.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import net.sharplab.springframework.security.webauthn.client.challenge.Challenge;
import net.sharplab.springframework.security.webauthn.client.challenge.DefaultChallenge;
import org.springframework.util.Base64Utils;

import java.io.IOException;

/**
 * Jackson Deserializer for Challenge
 */
public class ChallengeDeserializer extends StdDeserializer<Challenge> {
    public ChallengeDeserializer() {
        super(Challenge.class);
    }

    @Override
    public Challenge deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        byte[] challenge = Base64Utils.decodeFromUrlSafeString(p.getValueAsString());
        return new DefaultChallenge(challenge);
    }
}
