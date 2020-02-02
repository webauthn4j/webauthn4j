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

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test for Origin
 */
class OriginTest {

    private ObjectConverter objectConverter = new ObjectConverter();
    private JsonConverter jsonConverter = objectConverter.getJsonConverter();

    @Test
    void equals_test() {
        Origin https_examplecom_default = new Origin("https://example.com");
        Origin https_examplecom_443 = new Origin("https://example.com:443");
        Origin http_examplecom_default = new Origin("http://example.com");
        Origin http_examplecom_80 = new Origin("http://example.com:80");
        Origin http_examplecom_8080 = new Origin("http://example.com:8080");

        assertAll(
                () -> assertThat(https_examplecom_default).isEqualTo(https_examplecom_443),
                () -> assertThat(http_examplecom_default).isEqualTo(http_examplecom_80),
                () -> assertThat(http_examplecom_default).isNotEqualTo(http_examplecom_8080),
                () -> assertThat(http_examplecom_default).isNotEqualTo(https_examplecom_default)
        );
    }

    @Test
    void getter_test() {
        Origin https_examplecom_default = new Origin("https://example.com");
        assertAll(
                () -> assertThat(https_examplecom_default.getScheme()).isEqualTo("https"),
                () -> assertThat(https_examplecom_default.getHost()).isEqualTo("example.com"),
                () -> assertThat(https_examplecom_default.getPort()).isEqualTo(443)
        );
    }

    @Test
    void constructor_test() {
        Origin originA = new Origin("https://example.com");
        Origin originB = new Origin("https", "example.com", 443);

        assertThat(originA).isEqualTo(originB);
    }

    @Test
    void constructor_test_with_illegal_input() {
        assertThrows(IllegalArgumentException.class,
                () -> new Origin("ftp", "example.com", 80)
        );
    }

    @Test
    public void constructor_test_with_null_input() {
        assertThrows(IllegalArgumentException.class,
                () -> new Origin(null, "example.com", 80)
        );
    }

    @Test
    void single_string_constructor_test_with_illegal_input() {
        assertThrows(IllegalArgumentException.class,
                () -> new Origin("ftp://example.com")
        );
    }

    @Test
    void single_string_constructor_test_without_scheme_input() {
        assertThrows(IllegalArgumentException.class,
                () -> new Origin("example.com")
        );
    }

    @Test
    void hasCode_test() {
        Origin originA = new Origin("https://example.com");
        Origin originB = new Origin("https", "example.com", 443);

        assertThat(originA.hashCode()).isEqualTo(originB.hashCode());
    }

    @Test
    void fromString_test() {
        TestDTO dto = jsonConverter.readValue("{\"origin\":\"https://example.com\"}", TestDTO.class);
        assertThat(dto.origin).isEqualTo(new Origin("https://example.com"));
    }

    @Test
    void fromString_test_with_invalid_value() {
        assertThrows(DataConversionException.class,
                () -> jsonConverter.readValue("{\"origin\":\"file://example.com\"}", TestDTO.class)
        );
    }

    static class TestDTO {
        public Origin origin;
    }
}
