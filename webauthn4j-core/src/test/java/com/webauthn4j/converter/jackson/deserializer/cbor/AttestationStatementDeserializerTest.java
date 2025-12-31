/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.converter.jackson.deserializer.cbor;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.FIDOU2FAttestationStatement;
import com.webauthn4j.test.TestAttestationStatementUtil;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.exc.MismatchedInputException;
import tools.jackson.dataformat.cbor.CBORMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

/**
 * Test for AttestationStatementDeserializer
 */
class AttestationStatementDeserializerTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final CBORMapper cborMapper = objectConverter.getCborMapper();

    @Test
    void shouldDeserializeAttestationStatement() {
        //Given
        AttestationStatement source = TestAttestationStatementUtil.createFIDOU2FAttestationStatement();

        //When
        byte[] data = cborMapper.writeValueAsBytes(source);
        AttestationStatement obj = cborMapper.readValue(data, FIDOU2FAttestationStatement.class);

        //Then
        assertAll(
                () -> assertThat(obj).isInstanceOf(FIDOU2FAttestationStatement.class),
                () -> assertThat(obj).isEqualTo(source)
        );
    }

    @Test
    void shouldThrowExceptionForInvalidInput() {
        //Given
        byte[] invalidCbor = new byte[]{0x00, 0x01, 0x02}; // Invalid CBOR data

        //Then
        assertThatThrownBy(() -> cborMapper.readValue(invalidCbor, FIDOU2FAttestationStatement.class))
                .isInstanceOf(MismatchedInputException.class);
    }

    @Test
    void shouldThrowExceptionForNullInput() {
        //Then
        assertThatThrownBy(() -> cborMapper.readValue((byte[])null, FIDOU2FAttestationStatement.class))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
