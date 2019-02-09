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

package com.webauthn4j.util.jws;

import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;


public class JWAIdentifierTest {

    @Test
    public void create_test() throws InvalidFormatException {

        assertThat(JWAIdentifier.create("ES256")).isEqualTo(JWAIdentifier.ES256);
        assertThat(JWAIdentifier.create("ES384")).isEqualTo(JWAIdentifier.ES384);
        assertThat(JWAIdentifier.create("ES512")).isEqualTo(JWAIdentifier.ES512);
        assertThat(JWAIdentifier.create("RS1")).isEqualTo(JWAIdentifier.RS1);
        assertThat(JWAIdentifier.create("RS256")).isEqualTo(JWAIdentifier.RS256);
        assertThat(JWAIdentifier.create("RS384")).isEqualTo(JWAIdentifier.RS384);
        assertThat(JWAIdentifier.create("RS512")).isEqualTo(JWAIdentifier.RS512);
    }

    @Test
    public void name_test(){
        assertThat(JWAIdentifier.ES256.getName()).isEqualTo("ES256");
    }

    @Test(expected = InvalidFormatException.class)
    public void create_with_invalid_arg_test() throws InvalidFormatException {

        JWAIdentifier.create("invalid");
    }
}