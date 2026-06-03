package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.SignatureAlgorithm;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;
import tools.jackson.databind.exc.InvalidFormatException;

public class SignatureAlgorithmDeserializer extends StdDeserializer<SignatureAlgorithm> {

    public SignatureAlgorithmDeserializer() {
        super(SignatureAlgorithm.class);
    }

    @Override
    public SignatureAlgorithm deserialize(@NotNull JsonParser p, @NotNull DeserializationContext ctxt) {
        String value = p.getValueAsString();
        switch (value) {
            case "SHA256withECDSA":
                return SignatureAlgorithm.ES256;
            case "SHA384withECDSA":
                return SignatureAlgorithm.ES384;
            case "SHA512withECDSA":
                return SignatureAlgorithm.ES512;
            case "SHA1withRSA":
                return SignatureAlgorithm.RS1;
            case "SHA256withRSA":
                return SignatureAlgorithm.RS256;
            case "SHA384withRSA":
                return SignatureAlgorithm.RS384;
            case "SHA512withRSA":
                return SignatureAlgorithm.RS512;
            case "ed25519":
                return SignatureAlgorithm.Ed25519;
            case "SHA256withRSA/PSS":
                return SignatureAlgorithm.PS256;
            case "SHA384withRSA/PSS":
                return SignatureAlgorithm.PS384;
            case "SHA512withRSA/PSS":
                return SignatureAlgorithm.PS512;
            default:
                throw new InvalidFormatException(p, "value is out of range", value, SignatureAlgorithm.class);
        }
    }
}
