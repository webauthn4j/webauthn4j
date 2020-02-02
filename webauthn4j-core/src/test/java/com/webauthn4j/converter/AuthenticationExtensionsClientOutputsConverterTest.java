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

package com.webauthn4j.converter;


import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AuthenticationExtensionsClientOutputsConverterTest {

    private ObjectConverter objectConverter = new ObjectConverter();

    private AuthenticationExtensionsClientOutputsConverter target = new AuthenticationExtensionsClientOutputsConverter(objectConverter);

    @Test
    void convert_null_test() {
        assertThat(target.convert(null)).isNull();
    }

    @Test
    void convertToString_null_test() {
        assertThat(target.convertToString(null)).isNull();
    }
}