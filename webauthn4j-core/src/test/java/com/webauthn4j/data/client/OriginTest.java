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
    void getter_test() {
        Origin https_examplecom_default = new Origin("https://example.com");
        assertAll(
                () -> assertThat(https_examplecom_default.getScheme()).isEqualTo("https"),
                () -> assertThat(https_examplecom_default.getHost()).isEqualTo("example.com"),
                () -> assertThat(https_examplecom_default.getPort()).isEqualTo(443),
                () -> assertThat(https_examplecom_default.getSchemeSpecificPart()).isEqualTo("//example.com")
        );
        Origin https_examplecom_443 = new Origin("https://example.com:443");
        assertAll(
                () -> assertThat(https_examplecom_443.getScheme()).isEqualTo("https"),
                () -> assertThat(https_examplecom_443.getHost()).isEqualTo("example.com"),
                () -> assertThat(https_examplecom_443.getPort()).isEqualTo(443),
                () -> assertThat(https_examplecom_443.getSchemeSpecificPart()).isEqualTo("//example.com:443")
        );
        Origin android_apk_key_hash_sha1 = new Origin("android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");
        assertAll(
                () -> assertThat(android_apk_key_hash_sha1.getScheme()).isEqualTo("android"),
                () -> assertThat(android_apk_key_hash_sha1.getHost()).isNull(),
                () -> assertThat(android_apk_key_hash_sha1.getPort()).isNull(),
                () -> assertThat(android_apk_key_hash_sha1.getSchemeSpecificPart()).isEqualTo("apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck")
        );
        Origin android_apk_key_hash_sha256 = new Origin("android:apk-key-hash-sha256:aT5ZucZJ9N7oq3j3awG8J/NlKf8trfo6AAJB8deuuNo=");
        assertAll(
                () -> assertThat(android_apk_key_hash_sha256.getScheme()).isEqualTo("android"),
                () -> assertThat(android_apk_key_hash_sha256.getHost()).isNull(),
                () -> assertThat(android_apk_key_hash_sha256.getPort()).isNull(),
                () -> assertThat(android_apk_key_hash_sha256.getSchemeSpecificPart()).isEqualTo("apk-key-hash-sha256:aT5ZucZJ9N7oq3j3awG8J/NlKf8trfo6AAJB8deuuNo=")
        );
    }

    @Test
    void toString_test() {
        assertAll(
                () -> assertThat(new Origin("example.com")).hasToString("example.com"),
                () -> assertThat(new Origin("https://example.com")).hasToString("https://example.com"),
                () -> assertThat(new Origin("https://example.com:443")).hasToString("https://example.com:443"),
                () -> assertThat(new Origin("https://example.com:8443")).hasToString("https://example.com:8443"),
                () -> assertThat(new Origin("http://example.com")).hasToString("http://example.com"),
                () -> assertThat(new Origin("http://example.com:80")).hasToString("http://example.com:80"),
                () -> assertThat(new Origin("http://example.com:8080")).hasToString("http://example.com:8080"),
                () -> assertThat(new Origin("android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck")).hasToString("android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck"),
                () -> assertThat(new Origin("android:apk-key-hash-sha256:xT5ZucZJ9N7oq3j3awG8J/NlKf8trfo6AAJB8deuuNo=")).hasToString("android:apk-key-hash-sha256:xT5ZucZJ9N7oq3j3awG8J/NlKf8trfo6AAJB8deuuNo=")
        );
    }

    @Test
    @SuppressWarnings("deprecation")
    void constructor_test() {
        Origin originA = new Origin("https://example.com");
        Origin originB = new Origin("https", "example.com", 443);
        Origin originC = new Origin("HTTPs", "EXAMPLE.COM", 443);
        assertThat(originA)
                .isEqualTo(originB)
                .isEqualTo(originC);
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
    void create_with_null_test() {
        assertThrows(IllegalArgumentException.class,
                () -> Origin.create(null)
        );
    }

    @Test
    void explicit_port_notation_and_non_explicit_port_notation_comparison_test() {
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
    void apk_key_hash_equals_test() {
        Origin apkKeyHashSha1_1 = new Origin("android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");
        Origin apkKeyHashSha1_2 = new Origin("android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");
        Origin apkKeyHashSha256_1 = new Origin("android:apk-key-hash-sha256:xT5ZucZJ9N7oq3j3awG8J/NlKf8trfo6AAJB8deuuNo=");
        Origin https_examplecom_default = new Origin("https://example.com");

        assertAll(
                () -> assertThat(apkKeyHashSha1_1).isEqualTo(apkKeyHashSha1_2),
                () -> assertThat(apkKeyHashSha1_1).isNotEqualTo(https_examplecom_default),
                () -> assertThat(apkKeyHashSha1_1).isNotEqualTo(apkKeyHashSha256_1),
                () -> assertThat(apkKeyHashSha1_2).isNotEqualTo(https_examplecom_default)
        );
    }

    @Test
    void apk_key_hash_sha256_equals_test() {
        Origin apkCertHashSha256_1 = new Origin("android:apk-key-hash-sha256:xT5ZucZJ9N7oq3j3awG8J/NlKf8trfo6AAJB8deuuNo=");
        Origin apkCertHashSha256_2 = new Origin("android:apk-key-hash-sha256:xT5ZucZJ9N7oq3j3awG8J/NlKf8trfo6AAJB8deuuNo=");
        Origin apkCertHashSha1_1 = new Origin("android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");
        Origin https_examplecom_default = new Origin("https://example.com");

        assertAll(
                () -> assertThat(apkCertHashSha256_1).isEqualTo(apkCertHashSha256_2),
                () -> assertThat(apkCertHashSha256_1).isNotEqualTo(apkCertHashSha1_1),
                () -> assertThat(apkCertHashSha256_1).isNotEqualTo(https_examplecom_default),
                () -> assertThat(apkCertHashSha256_2).isNotEqualTo(https_examplecom_default)
        );
    }


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
    void https_equals_case_sensitivity_test() {
        Origin https_examplecom_default = new Origin("https://example.com");
        Origin https_examplecom_443 = new Origin("https://example.com:443");

        Origin HTTPS_examplecom_default = new Origin("HTTPS://example.com");
        Origin https_EXAMPLecoM_default = new Origin("https://EXAMPLe.coM");
        Origin https_EXAMPLecoM_443 = new Origin("https://EXAMPLe.coM:443");
        Origin HTTPS_EXAMPLECOM = new Origin("HTTPS://EXAMPLE.COM");
        Origin HTTPS_EXAMPLECOM_443 = new Origin("HTTPS://EXAMPLE.COM:443");

        assertAll(
                () -> assertThat(HTTPS_examplecom_default).isEqualTo(https_examplecom_default),
                () -> assertThat(https_EXAMPLecoM_default).isEqualTo(https_examplecom_default),
                () -> assertThat(https_EXAMPLecoM_443).isEqualTo(https_examplecom_default),
                () -> assertThat(HTTPS_EXAMPLECOM).isEqualTo(https_examplecom_default),
                () -> assertThat(HTTPS_EXAMPLECOM_443).isEqualTo(https_examplecom_default),

                () -> assertThat(HTTPS_examplecom_default).isEqualTo(https_examplecom_443),
                () -> assertThat(https_EXAMPLecoM_default).isEqualTo(https_examplecom_443),
                () -> assertThat(https_EXAMPLecoM_443).isEqualTo(https_examplecom_443),
                () -> assertThat(HTTPS_EXAMPLECOM).isEqualTo(https_examplecom_443),
                () -> assertThat(HTTPS_EXAMPLECOM_443).isEqualTo(https_examplecom_443)
        );
    }

    @Test
    void http_equals_case_sensitivity_test() {
        Origin http_localhost_default = new Origin("http://localhost");
        Origin http_localhost_80 = new Origin("http://localhost:80");

        Origin HTTP_localhost_default = new Origin("HTTP://localhost");
        Origin http_LocalHost_default = new Origin("http://LocalHost");
        Origin http_LocalHost_80 = new Origin("http://LocalHost:80");
        Origin HTTP_LOCALHOST = new Origin("HTTP://LOCALHOST");
        Origin HTTP_LOCALHOST_80 = new Origin("HTTP://LOCALHOST:80");

        assertAll(
                () -> assertThat(HTTP_localhost_default).isEqualTo(http_localhost_default),
                () -> assertThat(http_LocalHost_default).isEqualTo(http_localhost_default),
                () -> assertThat(http_LocalHost_80).isEqualTo(http_localhost_default),
                () -> assertThat(HTTP_LOCALHOST).isEqualTo(http_localhost_default),
                () -> assertThat(HTTP_LOCALHOST_80).isEqualTo(http_localhost_default),

                () -> assertThat(HTTP_localhost_default).isEqualTo(http_localhost_80),
                () -> assertThat(http_LocalHost_default).isEqualTo(http_localhost_80),
                () -> assertThat(http_LocalHost_80).isEqualTo(http_localhost_80),
                () -> assertThat(HTTP_LOCALHOST).isEqualTo(http_localhost_80),
                () -> assertThat(HTTP_LOCALHOST_80).isEqualTo(http_localhost_80)
        );
    }


    @Test
    @SuppressWarnings("deprecation")
    void hashCode_test() {
        Origin originA = new Origin("https://example.com");
        Origin originB = new Origin("https", "example.com", 443);
        Origin originC = new Origin("http://localhost:8080");
        Origin originD = new Origin("http", "localhost", 8080);
        Origin android_apk_key_hash_abc123_a = new Origin("android:apk-key-hash:abc123");
        Origin android_apk_key_hash_abc123_b = new Origin("android:apk-key-hash:abc123");
        Origin android_apk_key_hash_def456 = new Origin("android:apk-key-hash:def");
        Origin invalid_data = new Origin("invalid:data");

        assertThat(originA).hasSameHashCodeAs(originB);
        assertThat(originC).hasSameHashCodeAs(originD);
        assertThat(android_apk_key_hash_abc123_a).hasSameHashCodeAs(android_apk_key_hash_abc123_b);
        assertThat(android_apk_key_hash_abc123_a.hashCode()).isNotEqualTo(android_apk_key_hash_def456.hashCode());
        assertThat(android_apk_key_hash_abc123_a.hashCode()).isNotEqualTo(invalid_data.hashCode());
    }

    @Test
    void hashCode_https_case_insensitive_test() {
        Origin originA = new Origin("https://example.com");
        Origin originB = new Origin("HTTPS://example.com");
        Origin originC = new Origin("https://EXAMPLE.COM");
        Origin originD = new Origin("HTTPS://EXAMPLE.COM");
        Origin originE = new Origin("HTTPS://EXAMPLE.COM:443");


        assertThat(originA)
                .hasSameHashCodeAs(originB)
                .hasSameHashCodeAs(originC)
                .hasSameHashCodeAs(originD)
                .hasSameHashCodeAs(originE);
    }

    @Test
    void hashCode_http_case_insensitive_test() {
        Origin originA = new Origin("http://localhost");
        Origin originB = new Origin("HTTP://localhost");
        Origin originC = new Origin("http://LOCALHOST");
        Origin originD = new Origin("HTTP://LOCALHOST");
        Origin originE = new Origin("HTTP://LOCALHOST:80");


        assertThat(originA)
                .hasSameHashCodeAs(originB)
                .hasSameHashCodeAs(originC)
                .hasSameHashCodeAs(originD)
                .hasSameHashCodeAs(originE);
    }

    @Test
    void fromString_test() {
        TestDTO dto = jsonConverter.readValue("{\"origin\":\"https://example.com\"}", TestDTO.class);
        assertThat(dto.origin).isEqualTo(new Origin("https://example.com"));
    }

    @Test
    void apk_key_hash_fromString_test() {
        TestDTO dto = jsonConverter.readValue("{\"origin\":\"android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck\"}", TestDTO.class);
        assertThat(dto.origin).isEqualTo(new Origin("android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck"));
    }

    @Test
    void apk_key_hash_sha256_fromString_test() {
        TestDTO dto = jsonConverter.readValue("{\"origin\":\"android:apk-key-hash-sha256:xT5ZucZJ9N7oq3j3awG8J/NlKf8trfo6AAJB8deuuNo=\"}", TestDTO.class);
        assertThat(dto.origin).isEqualTo(new Origin("android:apk-key-hash-sha256:xT5ZucZJ9N7oq3j3awG8J/NlKf8trfo6AAJB8deuuNo="));
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
