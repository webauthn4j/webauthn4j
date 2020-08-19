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

package com.webauthn4j.server;

import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.test.TestDataUtil;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class ServerPropertyTest {

    @SuppressWarnings("deprecation")
    @Test
    void getOrigin_test(){
        Origin origin = new Origin("https://example.com");
        assertThat(new ServerProperty(origin, "example.com", new DefaultChallenge(), null).getOrigin()).isEqualTo(origin);
        assertThat(new ServerProperty(Collections.emptyList(), "example.com", new DefaultChallenge(), null).getOrigin()).isNull();;
        assertThat(new ServerProperty((Origin) null, "example.com", new DefaultChallenge(), null).getOrigin()).isNull();;
    }

    @Test
    void equals_hashCode_test() {
        Challenge challenge = new DefaultChallenge();
        ServerProperty serverPropertyA = TestDataUtil.createServerProperty(challenge);
        ServerProperty serverPropertyB = TestDataUtil.createServerProperty(challenge);

        assertAll(
                () -> assertThat(serverPropertyA).isEqualTo(serverPropertyB),
                () -> assertThat(serverPropertyA).hasSameHashCodeAs(serverPropertyB)
        );
    }
}
