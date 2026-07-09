package com.webauthn4j.converter.jackson.deserializer.cbor;

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
        var cborMapper = objectConverter.getCborMapper();
        byte[] cborNeg7 = new byte[]{0x26}; // CBOR integer -7
        var result = cborMapper.readValue(cborNeg7, COSEAlgorithmIdentifier.class);
        assertThat(result).isEqualTo(COSEAlgorithmIdentifier.ES256);
    }

    @Test
    void deserialize_with_string_value_should_throw() {
        var cborMapper = objectConverter.getCborMapper();
        byte[] cborString = new byte[]{0x62, 0x2D, 0x37}; // CBOR text string "-7"
        assertThrows(InvalidFormatException.class, () ->
                cborMapper.readValue(cborString, COSEAlgorithmIdentifier.class)
        );
    }

    @Test
    void deserialize_with_boolean_value_should_throw() {
        var cborMapper = objectConverter.getCborMapper();
        byte[] cborTrue = new byte[]{(byte) 0xF5}; // CBOR true
        assertThrows(InvalidFormatException.class, () ->
                cborMapper.readValue(cborTrue, COSEAlgorithmIdentifier.class)
        );
    }
}
