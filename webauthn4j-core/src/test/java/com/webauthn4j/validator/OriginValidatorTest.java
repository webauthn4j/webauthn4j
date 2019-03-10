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

package com.webauthn4j.validator;

import com.webauthn4j.response.client.ClientDataType;
import com.webauthn4j.response.client.CollectedClientData;
import com.webauthn4j.response.client.Origin;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.validator.exception.BadOriginException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test for OriginValidator
 */
class OriginValidatorTest {

    private OriginValidator target = new OriginValidator();

    @Test
    void test() {
        Origin originA = new Origin("https://example.com:14443");
        Origin originB = new Origin("https://example.com:14443");

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.CREATE, TestDataUtil.createChallenge(), originA, null);
        ServerProperty serverProperty = new ServerProperty(originB, "example.com", TestDataUtil.createChallenge(), null);
        target.validate(collectedClientData, serverProperty);
    }

    @Test
    void test_with_not_equal_origins() {
        Origin originA = new Origin("https://example.com:14443");
        Origin originB = new Origin("http://example.com");

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.CREATE, TestDataUtil.createChallenge(), originA, null);
        ServerProperty serverProperty = new ServerProperty(originB, "example.com", TestDataUtil.createChallenge(), null);
        assertThrows(BadOriginException.class,
                () -> target.validate(collectedClientData, serverProperty)
        );
    }
}
