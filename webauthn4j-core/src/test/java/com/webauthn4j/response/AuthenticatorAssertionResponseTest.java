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

package com.webauthn4j.response;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class AuthenticatorAssertionResponseTest {

    @Test
    public void getUserHandle_test(){
        AuthenticatorAssertionResponse instance = new AuthenticatorAssertionResponse(new byte[0], new byte[1], new byte[2], new byte[3]);
        assertThat(instance.getUserHandle()).isEqualTo(new byte[3]);
    }

    @Test
    public void equals_hashCode_test(){
        AuthenticatorAssertionResponse instanceA = new AuthenticatorAssertionResponse(new byte[0], new byte[1], new byte[2], new byte[3]);
        AuthenticatorAssertionResponse instanceB = new AuthenticatorAssertionResponse(new byte[0], new byte[1], new byte[2], new byte[3]);

        assertThat(instanceA).isEqualTo(instanceB);
        assertThat(instanceA).hasSameHashCodeAs(instanceB);
    }

}