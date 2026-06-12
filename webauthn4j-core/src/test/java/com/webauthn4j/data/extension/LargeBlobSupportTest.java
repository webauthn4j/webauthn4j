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

package com.webauthn4j.data.extension;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LargeBlobSupportTest {

    @Test
    void create_from_preferred_string() {
        assertThat(LargeBlobSupport.create("preferred")).isEqualTo(LargeBlobSupport.PREFERRED);
    }

    @Test
    void create_from_required_string() {
        assertThat(LargeBlobSupport.create("required")).isEqualTo(LargeBlobSupport.REQUIRED);
    }

    @SuppressWarnings("ResultOfMethodCallIgnored")
    @Test
    void create_from_invalid_string_throws() {
        assertThatThrownBy(() -> LargeBlobSupport.create("invalid")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void toString_returns_string_value() {
        assertThat(LargeBlobSupport.PREFERRED).hasToString("preferred");
        assertThat(LargeBlobSupport.REQUIRED).hasToString("required");
    }

}
