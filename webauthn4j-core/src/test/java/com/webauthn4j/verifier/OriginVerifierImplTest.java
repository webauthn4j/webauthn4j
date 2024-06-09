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

package com.webauthn4j.verifier;

import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.verifier.exception.BadOriginException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Arrays;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test for OriginValidator
 */
class OriginVerifierImplTest {

    private final OriginVerifierImpl target = new OriginVerifierImpl();

    @ParameterizedTest
    @ValueSource(strings = {
            "https://example.com:14443", // web
            "android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck", // android:apk-key-hash
            "android:apk-key-hash-sha256:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck" // android:apk-key-hash-sha256
    })
    void test(String origin) {
        Origin originA = new Origin(origin);
        Origin originB = new Origin(origin);

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.WEBAUTHN_CREATE, TestDataUtil.createChallenge(), originA, null);
        ServerProperty serverProperty = new ServerProperty(originB, "example.com", TestDataUtil.createChallenge(), null);
        target.verify(collectedClientData, serverProperty);
    }

    @Test
    void multiple_origins_test() {
        final Origin originA = new Origin("https://example.com:14443");
        final Origin originB = new Origin("http://localhost:9090");
        final Origin originC = new Origin("android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");
        final Origin originD = new Origin("android:apk-key-hash-sha256:qSiQ5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");

        final ServerProperty serverProperty = new ServerProperty(new HashSet<>(Arrays.asList(originA, originB, originC, originD)),
                "example.com", TestDataUtil.createChallenge(), null);

        final CollectedClientData collectedClientDataA = new CollectedClientData(ClientDataType.WEBAUTHN_CREATE,
                TestDataUtil.createChallenge(), originA, null);
        final CollectedClientData collectedClientDataB = new CollectedClientData(ClientDataType.WEBAUTHN_CREATE,
                TestDataUtil.createChallenge(), originB, null);
        final CollectedClientData collectedClientDataC = new CollectedClientData(ClientDataType.WEBAUTHN_GET,
                TestDataUtil.createChallenge(), originC, null);
        final CollectedClientData collectedClientDataD = new CollectedClientData(ClientDataType.WEBAUTHN_GET,
                TestDataUtil.createChallenge(), originD, null);

        target.verify(collectedClientDataA, serverProperty);
        target.verify(collectedClientDataB, serverProperty);
        target.verify(collectedClientDataC, serverProperty);
        target.verify(collectedClientDataD, serverProperty);
    }

    @Test
    void multiple_origins_test_with_invalid_origin() {
        final Origin originA = new Origin("https://example.com:14443");
        final Origin originB = new Origin("http://localhost:9090");
        final Origin originC = new Origin("android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");
        final Origin originD = new Origin("android:apk-key-hash-sha256:qSiQ5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");

        final Origin badOriginA = new Origin("https://example.phish.com:14443");
        final Origin badOriginB = new Origin("http://phish.localhost:9090");
        final Origin badOriginC = new Origin("android:apk-key-hash:0pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");
        final Origin badOriginD = new Origin("android:apk-key-hash-sha256:0qSiQ5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");

        final ServerProperty serverProperty = new ServerProperty(new HashSet<>(Arrays.asList(originA, originB, originC, originD)),
                "example.com", TestDataUtil.createChallenge(), null);

        final CollectedClientData collectedClientDataA = new CollectedClientData(ClientDataType.WEBAUTHN_CREATE,
                TestDataUtil.createChallenge(), badOriginA, null);
        final CollectedClientData collectedClientDataB = new CollectedClientData(ClientDataType.WEBAUTHN_CREATE,
                TestDataUtil.createChallenge(), badOriginB, null);
        final CollectedClientData collectedClientDataC = new CollectedClientData(ClientDataType.WEBAUTHN_GET,
                TestDataUtil.createChallenge(), badOriginC, null);
        final CollectedClientData collectedClientDataD = new CollectedClientData(ClientDataType.WEBAUTHN_GET,
                TestDataUtil.createChallenge(), badOriginD, null);


        assertThrows(BadOriginException.class,
                () -> target.verify(collectedClientDataA, serverProperty)
        );
        assertThrows(BadOriginException.class,
                () -> target.verify(collectedClientDataB, serverProperty)
        );
        assertThrows(BadOriginException.class,
                () -> target.verify(collectedClientDataC, serverProperty)
        );
        assertThrows(BadOriginException.class,
                () -> target.verify(collectedClientDataD, serverProperty)
        );
    }

    @SuppressWarnings("java:S5976")
    @Test
    void test_with_not_equal_origins() {
        Origin originA = new Origin("https://example.com:14443");
        Origin originB = new Origin("http://example.com");

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.WEBAUTHN_CREATE, TestDataUtil.createChallenge(), originA, null);
        ServerProperty serverProperty = new ServerProperty(originB, "example.com", TestDataUtil.createChallenge(), null);
        assertThrows(BadOriginException.class,
                () -> target.verify(collectedClientData, serverProperty)
        );
    }

    @SuppressWarnings("java:S5976")
    @Test
    void apk_key_hash_test_with_not_equal_origins() {
        Origin originA = new Origin("android:apk-key-hash:aNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");
        Origin originB = new Origin("android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.WEBAUTHN_CREATE, TestDataUtil.createChallenge(), originA, null);
        ServerProperty serverProperty = new ServerProperty(originB, "1.example.com", TestDataUtil.createChallenge(), null);
        assertThrows(BadOriginException.class,
                () -> target.verify(collectedClientData, serverProperty)
        );
    }

    @SuppressWarnings("java:S5976")
    @Test
    void apk_key_hash_sha256_test_with_not_equal_origins() {
        Origin originA = new Origin("android:apk-key-hash-sha256:aNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");
        Origin originB = new Origin("android:apk-key-hash-sha256:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.WEBAUTHN_CREATE, TestDataUtil.createChallenge(), originA, null);
        ServerProperty serverProperty = new ServerProperty(originB, "2.example.com", TestDataUtil.createChallenge(), null);
        assertThrows(BadOriginException.class,
                () -> target.verify(collectedClientData, serverProperty)
        );
    }

    @SuppressWarnings("java:S5976")
    @Test
    void apk_key_hash_sha256_test_with_not_equal_origins_apk_key_hash_sha1() {
        Origin originA = new Origin("android:apk-key-hash-sha256:aNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");
        Origin originB = new Origin("android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.WEBAUTHN_CREATE, TestDataUtil.createChallenge(), originA, null);
        ServerProperty serverProperty = new ServerProperty(originB, "3.example.com", TestDataUtil.createChallenge(), null);
        assertThrows(BadOriginException.class,
                () -> target.verify(collectedClientData, serverProperty)
        );
    }

    @SuppressWarnings("java:S5976")
    @Test
    void apk_key_hash_sha1_test_with_not_equal_origins_apk_key_hash_sha256() {
        Origin originA = new Origin("android:apk-key-hash:aNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");
        Origin originB = new Origin("android:apk-key-hash-sha256:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.WEBAUTHN_CREATE, TestDataUtil.createChallenge(), originA, null);
        ServerProperty serverProperty = new ServerProperty(originB, "4.example.com", TestDataUtil.createChallenge(), null);
        assertThrows(BadOriginException.class,
                () -> target.verify(collectedClientData, serverProperty)
        );
    }


}
