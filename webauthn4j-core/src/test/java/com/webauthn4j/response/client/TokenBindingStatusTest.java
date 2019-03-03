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

package com.webauthn4j.response.client;

import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TokenBindingStatusTest {

    @Test
    void create_with_illegal_value_test() {
        assertThrows(InvalidFormatException.class,
                () -> TokenBindingStatus.create("illegal")
        );
    }

    @Test
    void create_test() throws InvalidFormatException {
        TokenBindingStatus status = TokenBindingStatus.create("supported");
        assertThat(status).isEqualTo(TokenBindingStatus.SUPPORTED);
    }

    @Test
    void create_with_null_value_test() throws InvalidFormatException {
        TokenBindingStatus status = TokenBindingStatus.create(null);
        assertThat(status).isNull();
    }
}
