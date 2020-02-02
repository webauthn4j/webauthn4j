/*
 * Copyright 2018 the original author or authors.
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

package com.webauthn4j.data.attestation.statement;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

class COSEKeyTypeTest {

    private ObjectConverter objectConverter = new ObjectConverter();
    private JsonConverter jsonConverter = objectConverter.getJsonConverter();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(COSEKeyType.create(0)).isEqualTo(COSEKeyType.RESERVED),
                () -> assertThat(COSEKeyType.create(1)).isEqualTo(COSEKeyType.OKP),
                () -> assertThat(COSEKeyType.create(2)).isEqualTo(COSEKeyType.EC2),
                () -> assertThat(COSEKeyType.create(3)).isEqualTo(COSEKeyType.RSA),
                () -> assertThat(COSEKeyType.create(4)).isEqualTo(COSEKeyType.SYMMETRIC),
                //noinspection ResultOfMethodCallIgnored
                () -> assertThrows(IllegalArgumentException.class,
                        () -> COSEKeyType.create(-1)
                )
        );
    }

    @Test
    void getValueTest() {
        assertThat(COSEKeyType.OKP.getValue()).isEqualTo(1);
    }

    @Test
    void fromString_test() {
        TestDTO dto = jsonConverter.readValue("{\"cose_key_type\":0}", TestDTO.class);
        assertThat(dto.cose_key_type).isEqualTo(COSEKeyType.RESERVED);
    }

    @Test
    void fromString_test_with_invalid_value() {
        assertThrows(DataConversionException.class,
                () -> jsonConverter.readValue("{\"cose_key_type\":-1}", TestDTO.class)
        );
    }

    static class TestDTO {
        public COSEKeyType cose_key_type;
    }
}
