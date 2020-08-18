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

import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test for Origin
 */
class OriginTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final JsonConverter jsonConverter = objectConverter.getJsonConverter();

    @Test
    void equals_test() {
        Origin https_examplecom_default = new Origin("https://example.com");
        Origin https_examplecom_443 = new Origin("https://example.com:443");
        Origin http_examplecom_default = new Origin("http://example.com");
        Origin http_examplecom_80 = new Origin("http://example.com:80");
        Origin http_examplecom_8080 = new Origin("http://example.com:8080");
        Origin android_apk_key_hash_abc123_a = new Origin("android:apk-key-hash:abc123");
        Origin android_apk_key_hash_abc123_b = new Origin("android:apk-key-hash:abc123");
        Origin android_apk_key_hash_def456 = new Origin("android:apk-key-hash:def");

        assertAll(
                () -> assertThat(https_examplecom_default).isEqualTo(https_examplecom_443),
                () -> assertThat(http_examplecom_default).isEqualTo(http_examplecom_80),
                () -> assertThat(http_examplecom_default).isNotEqualTo(http_examplecom_8080),
                () -> assertThat(http_examplecom_default).isNotEqualTo(https_examplecom_default),
                () -> assertThat(android_apk_key_hash_abc123_a).isEqualTo(android_apk_key_hash_abc123_b),
                () -> assertThat(android_apk_key_hash_abc123_a).isNotEqualTo(android_apk_key_hash_def456)
        );
    }

    @Test
    void getter_test() {
        Origin https_examplecom_default = new Origin("https://example.com");
        assertAll(
                () -> assertThat(https_examplecom_default.getScheme()).isEqualTo("https"),
                () -> assertThat(https_examplecom_default.getHost()).isEqualTo("example.com"),
                () -> assertThat(https_examplecom_default.getPort()).isEqualTo(443),
                () -> assertThat(https_examplecom_default.getSchemeSpecificPart()).isNull()
        );
        Origin https_examplecom_443 = new Origin("https://example.com:443");
        assertAll(
                () -> assertThat(https_examplecom_443.getScheme()).isEqualTo("https"),
                () -> assertThat(https_examplecom_443.getHost()).isEqualTo("example.com"),
                () -> assertThat(https_examplecom_443.getPort()).isEqualTo(443),
                () -> assertThat(https_examplecom_443.getSchemeSpecificPart()).isNull()
        );
        Origin android_apk_key_hash_abc123 = new Origin("android:apk-key-hash:abc123");
        assertAll(
                () -> assertThat(android_apk_key_hash_abc123.getScheme()).isEqualTo("android"),
                () -> assertThat(android_apk_key_hash_abc123.getHost()).isNull(),
                () -> assertThat(android_apk_key_hash_abc123.getPort()).isNull(),
                () -> assertThat(android_apk_key_hash_abc123.getSchemeSpecificPart()).isEqualTo("apk-key-hash:abc123")
        );
    }

    @Test
    void toString_test(){
        assertAll(
                ()-> assertThat(new Origin("example.com")).hasToString("example.com"),
                ()-> assertThat(new Origin("https://example.com")).hasToString("https://example.com"),
                ()-> assertThat(new Origin("https://example.com:443")).hasToString("https://example.com:443"),
                ()-> assertThat(new Origin("https://example.com:8443")).hasToString("https://example.com:8443"),
                ()-> assertThat(new Origin("http://example.com")).hasToString("http://example.com"),
                ()-> assertThat(new Origin("http://example.com:80")).hasToString("http://example.com:80"),
                ()-> assertThat(new Origin("http://example.com:8080")).hasToString("http://example.com:8080"),
                ()-> assertThat(new Origin("android:apk-key-hash:abc123")).hasToString("android:apk-key-hash:abc123")
        );
    }

    @Test
    @SuppressWarnings("deprecation")
    void constructor_test() {
        Origin originA = new Origin("https://example.com");
        Origin originB = new Origin("https", "example.com", 443);

        assertThat(originA).isEqualTo(originB);
    }

    @Test
    @SuppressWarnings("deprecation")
    void constructor_test_with_illegal_input() {
        assertThrows(IllegalArgumentException.class,
                () -> new Origin("ftp", "example.com", 80)
        );
    }

    @Test
    @SuppressWarnings("deprecation")
    void constructor_test_with_null_input() {
        assertThrows(IllegalArgumentException.class,
                () -> new Origin(null, "example.com", 80)
        );
    }

    @Test
    void create_with_null_test(){
        assertThrows(IllegalArgumentException.class,
                () -> Origin.create(null)
        );
    }

    @Test
    void explicit_port_notation_and_non_explicit_port_notation_comparison_test(){
        assertThat(new Origin("https://example.com:443")).isEqualTo(new Origin("https://example.com"));
        assertThat(new Origin("https://example.com:443")).hasToString("https://example.com:443");
    }


    @Test
    void single_string_constructor_test_with_illegal_input() {
        // invalid scheme is to be handled by validator
        assertThatCode(() -> new Origin("ftp://example.com")).doesNotThrowAnyException();
    }

    @Test
    void single_string_constructor_test_without_scheme_input() {
        // invalid scheme is to be handled by validator
        assertThatCode(() -> new Origin("example.com")).doesNotThrowAnyException();
    }

    @Test
    @SuppressWarnings("deprecation")
    void hasCode_test() {
        Origin originA = new Origin("https://example.com");
        Origin originB = new Origin("https", "example.com", 443);
        Origin android_apk_key_hash_abc123_a = new Origin("android:apk-key-hash:abc123");
        Origin android_apk_key_hash_abc123_b = new Origin("android:apk-key-hash:abc123");
        Origin android_apk_key_hash_def456 = new Origin("android:apk-key-hash:def");

        assertThat(originA).hasSameHashCodeAs(originB);
        assertThat(android_apk_key_hash_abc123_a).hasSameHashCodeAs(android_apk_key_hash_abc123_b);
        assertThat(android_apk_key_hash_abc123_a.hashCode()).isNotEqualTo(android_apk_key_hash_def456.hashCode());
    }

    @Test
    void fromString_test() {
        TestDTO dto = jsonConverter.readValue("{\"origin\":\"https://example.com\"}", TestDTO.class);
        assertThat(dto.origin).isEqualTo(new Origin("https://example.com"));
    }

    @Test
    void fromString_test_with_invalid_value() {
        // invalid scheme is to be handled by validator
        assertThatCode(() -> jsonConverter.readValue("{\"origin\":\"file://example.com\"}", TestDTO.class)).doesNotThrowAnyException();
    }

    static class TestDTO {
        public Origin origin;
    }
}
