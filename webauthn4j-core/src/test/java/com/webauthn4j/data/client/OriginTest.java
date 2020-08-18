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

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final JsonConverter jsonConverter = objectConverter.getJsonConverter();

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
    void apk_key_hash_equals_test() {
        Origin apkKeyHashSha1_1 = new Origin("android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");
        Origin apkKeyHashSha1_2 = new Origin("android:apk-key-hash","pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");
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
        Origin apkCertHashSha256_2 = new Origin("android:apk-key-hash-sha256","xT5ZucZJ9N7oq3j3awG8J/NlKf8trfo6AAJB8deuuNo=");
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
    void getter_test() {
        Origin https_examplecom_default = new Origin("https://example.com");
        assertAll(
                () -> assertThat(https_examplecom_default.getScheme()).isEqualTo("https"),
                () -> assertThat(https_examplecom_default.getHost()).isEqualTo("example.com"),
                () -> assertThat(https_examplecom_default.getPort()).isEqualTo(443),
                () -> assertThat(https_examplecom_default.getApkSigningCertHash()).isNull(),
                () -> assertThat(https_examplecom_default.getOriginType()).isEqualTo(Origin.OriginType.WEB)
        );
    }

    @Test
    void apk_key_hash_getter_test() {
        final Origin apkKeyHashSha1_1 = new Origin("android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");
        assertAll(
                () -> assertThat(apkKeyHashSha1_1.getScheme()).isEqualTo("android:apk-key-hash"),
                () -> assertThat(apkKeyHashSha1_1.getHost()).isNull(),
                () -> assertThat(apkKeyHashSha1_1.getPort()).isEqualTo(-1),
                () -> assertThat(apkKeyHashSha1_1.getApkSigningCertHash()).isEqualTo("pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck"),
                () -> assertThat(apkKeyHashSha1_1.getOriginType()).isEqualTo(Origin.OriginType.APK_KEY_HASH)
        );
        final Origin apkKeyHashSha1_2 = new Origin("android:apk-key-hash","oMiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");
        assertAll(
                () -> assertThat(apkKeyHashSha1_2.getScheme()).isEqualTo("android:apk-key-hash"),
                () -> assertThat(apkKeyHashSha1_2.getHost()).isNull(),
                () -> assertThat(apkKeyHashSha1_2.getPort()).isEqualTo(-1),
                () -> assertThat(apkKeyHashSha1_2.getApkSigningCertHash()).isEqualTo("oMiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck"),
                () -> assertThat(apkKeyHashSha1_2.getOriginType()).isEqualTo(Origin.OriginType.APK_KEY_HASH)
        );
    }

    @Test
    void apk_key_hash_sha256_getter_test() {
        final Origin apkKeyHashSha256_1 = new Origin("android:apk-key-hash-sha256:aT5ZucZJ9N7oq3j3awG8J/NlKf8trfo6AAJB8deuuNo=");
        assertAll(
                () -> assertThat(apkKeyHashSha256_1.getScheme()).isEqualTo("android:apk-key-hash-sha256"),
                () -> assertThat(apkKeyHashSha256_1.getHost()).isNull(),
                () -> assertThat(apkKeyHashSha256_1.getPort()).isEqualTo(-1),
                () -> assertThat(apkKeyHashSha256_1.getApkSigningCertHash()).isEqualTo("aT5ZucZJ9N7oq3j3awG8J/NlKf8trfo6AAJB8deuuNo="),
                () -> assertThat(apkKeyHashSha256_1.getOriginType()).isEqualTo(Origin.OriginType.APK_KEY_HASH)
        );
        final Origin apkKeyHashSha256_2 = new Origin("android:apk-key-hash-sha256","xT5ZucZJ9N7oq3j3awG8J/NlKf8trfo6AAJB8deuuNo=");
        assertAll(
                () -> assertThat(apkKeyHashSha256_2.getScheme()).isEqualTo("android:apk-key-hash-sha256"),
                () -> assertThat(apkKeyHashSha256_2.getHost()).isNull(),
                () -> assertThat(apkKeyHashSha256_2.getPort()).isEqualTo(-1),
                () -> assertThat(apkKeyHashSha256_2.getApkSigningCertHash()).isEqualTo("xT5ZucZJ9N7oq3j3awG8J/NlKf8trfo6AAJB8deuuNo="),
                () -> assertThat(apkKeyHashSha256_2.getOriginType()).isEqualTo(Origin.OriginType.APK_KEY_HASH)
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
    void constructor_test_with_null_input() {
        assertThrows(IllegalArgumentException.class,
                () -> new Origin(null, "example.com", 80)
        );
    }

    @Test
    void constructor_test_with_null_originstr() {
        assertThrows(IllegalArgumentException.class,
                () -> new Origin(null)
        );
    }

    @Test
    void single_string_constructor_test_with_illegal_input() {
        assertThrows(IllegalArgumentException.class,
                () -> new Origin("ftp://example.com")
        );
    }

    @Test
    void apk_key_hash_constructor_test_with_illegal_input() {
        assertThrows(IllegalArgumentException.class,
                () -> new Origin("http","example.com")
        );
        assertThrows(IllegalArgumentException.class,
                () -> new Origin("https","example.com")
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

        assertThat(originA).hasSameHashCodeAs(originB);
    }

    @Test
    void apk_key_hash_hashCode_test() {
        final Origin apkKeyHashSha1_1 = new Origin("android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");
        final Origin apkKeyHashSha1_2 = new Origin("android:apk-key-hash","pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");

        final Origin apkKeyHashSha256_1 = new Origin("android:apk-key-hash-sha256","pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");

        assertThat(apkKeyHashSha1_1.hashCode()).isEqualTo(apkKeyHashSha1_2.hashCode());
        assertThat(apkKeyHashSha1_1.hashCode()).isNotEqualTo(apkKeyHashSha256_1.hashCode());
    }

    @Test
    void apk_key_hash_sha256_hashCode_test() {
        final Origin apkKeyHashSha256_1 = new Origin("android:apk-key-hash-sha256:xT5ZucZJ9N7oq3j3awG8J/NlKf8trfo6AAJB8deuuNo=");
        final Origin apkKeyHashSha256_2 = new Origin("android:apk-key-hash-sha256","xT5ZucZJ9N7oq3j3awG8J/NlKf8trfo6AAJB8deuuNo=");

        final Origin apkKeyHashSha1_1 = new Origin("android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");

        assertThat(apkKeyHashSha256_1.hashCode()).isEqualTo(apkKeyHashSha256_2.hashCode());
        assertThat(apkKeyHashSha1_1.hashCode()).isNotEqualTo(apkKeyHashSha256_1.hashCode());

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
    void apk_key_hash_toString_test() {
        assertThat(new Origin("android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck")).hasToString("android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");
    }

    @Test
    void apk_key_hash_sha256_toString_test() {
        assertThat(new Origin("android:apk-key-hash-sha256:xT5ZucZJ9N7oq3j3awG8J/NlKf8trfo6AAJB8deuuNo=")).hasToString("android:apk-key-hash-sha256:xT5ZucZJ9N7oq3j3awG8J/NlKf8trfo6AAJB8deuuNo=");
    }

    @Test
    void toString_test() {
        Origin https_examplecom_default = new Origin("https://example.com");
        Origin https_examplecom_443 = new Origin("https://example.com:443");
        Origin https_examplecom_8443 = new Origin("https://example.com:8443");

        Origin http_examplecom_default = new Origin("http://example.com");
        Origin http_examplecom_80 = new Origin("http://example.com:80");
        Origin http_examplecom_8080 = new Origin("http://example.com:8080");

        assertAll(
                () -> assertThat(https_examplecom_default).hasToString("https://example.com"),
                () -> assertThat(https_examplecom_443).hasToString("https://example.com"),
                () -> assertThat(https_examplecom_8443).hasToString("https://example.com:8443"),
                () -> assertThat(http_examplecom_default).hasToString("http://example.com"),
                () -> assertThat(http_examplecom_80).hasToString("http://example.com"),
                () -> assertThat(http_examplecom_8080).hasToString("http://example.com:8080")
        );
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
