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

package com.webauthn4j.converter.jackson.deserializer;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.client.CollectedClientData;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test for ChallengeDeserializer
 */
class ChallengeDeserializerTest {

    private ObjectConverter objectConverter = new ObjectConverter();
    private JsonConverter jsonConverter = objectConverter.getJsonConverter();

    @Test
    void test() {


        //Given
        String input = "{ \"challenge\" : \"\" }";

        //When
        CollectedClientData result = jsonConverter.readValue(input, CollectedClientData.class);

        //Then
        assertAll(
                () -> assertThat(result).extracting("challenge").isNotNull(),
                () -> assertThat(result.getChallenge().getValue()).hasSize(0)
        );
    }

    @Test
    void null_test() {

        //Given
        String input = "{ \"challenge\" : null }";

        //When
        CollectedClientData result = jsonConverter.readValue(input, CollectedClientData.class);

        //Then
        assertThat(result).extracting("challenge").isNotNull();
        assertThat(result.getChallenge()).isNull();
    }

    @Test
    void invalid_value_test() {

        //Given
        String input = "{ \"challenge\" : \"ddddd\" }";

        //When
        assertThrows(DataConversionException.class,
                () -> jsonConverter.readValue(input, CollectedClientData.class)
        );
    }
}
