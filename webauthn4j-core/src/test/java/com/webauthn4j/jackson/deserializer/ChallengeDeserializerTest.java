/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.jackson.deserializer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.test.TestUtil;
import org.junit.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for ChallengeDeserializer
 */
public class ChallengeDeserializerTest {

    @Test
    public void test() throws IOException {
        ObjectMapper objectMapper = TestUtil.createJsonMapper();

        //Given
        String input = "{ \"challenge\" : \"\" }";

        //When
        CollectedClientData result = objectMapper.readValue(input, CollectedClientData.class);

        //Then
        assertThat(result).extracting("challenge").isNotNull();
        assertThat(result.getChallenge().getValue()).hasSize(0);
    }
}
