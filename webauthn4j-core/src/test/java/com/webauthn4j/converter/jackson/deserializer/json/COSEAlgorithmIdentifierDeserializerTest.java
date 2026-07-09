package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.exc.InvalidFormatException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class COSEAlgorithmIdentifierDeserializerTest {

    private final ObjectConverter objectConverter = new ObjectConverter();

    @Test
    void deserialize_with_integer_value() {
        var jsonMapper = objectConverter.getJsonMapper();
        var result = jsonMapper.readValue("-7", COSEAlgorithmIdentifier.class);
        assertThat(result).isEqualTo(COSEAlgorithmIdentifier.ES256);
    }

    @Test
    void deserialize_with_string_value_should_throw() {
        var jsonMapper = objectConverter.getJsonMapper();
        assertThrows(InvalidFormatException.class, () ->
                jsonMapper.readValue("\"-7\"", COSEAlgorithmIdentifier.class)
        );
    }

    @Test
    void deserialize_with_boolean_value_should_throw() {
        var jsonMapper = objectConverter.getJsonMapper();
        assertThrows(InvalidFormatException.class, () ->
                jsonMapper.readValue("true", COSEAlgorithmIdentifier.class)
        );
    }
}
