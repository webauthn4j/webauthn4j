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

package com.webauthn4j.data.client;

import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.test.TestDataUtil;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertAll;

class CollectedClientDataTest {

    @Test
    void constructor_test(){
        Challenge challenge = new DefaultChallenge();
        Origin origin = Origin.create("http://example.com");
        assertAll(
                () -> assertThatCode(()-> new CollectedClientData(ClientDataType.CREATE, challenge, origin, true,null)).doesNotThrowAnyException(),
                () -> assertThatCode(()-> new CollectedClientData(ClientDataType.CREATE, challenge, origin, null)).doesNotThrowAnyException(),
                () -> assertThatThrownBy(()-> new CollectedClientData(null, challenge, origin, null)).isInstanceOf(IllegalArgumentException.class),
                () -> assertThatThrownBy(()-> new CollectedClientData(ClientDataType.CREATE, null, origin, null)).isInstanceOf(IllegalArgumentException.class),
                () -> assertThatThrownBy(()-> new CollectedClientData(ClientDataType.CREATE, challenge, null, null)).isInstanceOf(IllegalArgumentException.class)
        );
    }

    @Test
    void equals_hashCode_test() {
        Challenge challenge = TestDataUtil.createChallenge();
        CollectedClientData collectedClientDataA = TestDataUtil.createClientData(ClientDataType.GET, challenge);
        CollectedClientData collectedClientDataB = TestDataUtil.createClientData(ClientDataType.GET, challenge);
        assertAll(
                () -> assertThat(collectedClientDataA).isEqualTo(collectedClientDataB),
                () -> assertThat(collectedClientDataA).hasSameHashCodeAs(collectedClientDataB)
        );
    }
}
