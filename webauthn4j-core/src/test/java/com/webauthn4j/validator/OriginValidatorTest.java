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

package com.webauthn4j.validator;

import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.validator.exception.BadOriginException;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test for OriginValidator
 */
class OriginValidatorTest {

    private final OriginValidator target = new OriginValidator();

    @Test
    void test() {
        Origin originA = new Origin("https://example.com:14443");
        Origin originB = new Origin("https://example.com:14443");

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.CREATE, TestDataUtil.createChallenge(), originA, null);
        ServerProperty serverProperty = new ServerProperty(originB, "example.com", TestDataUtil.createChallenge(), null);
        target.validate(collectedClientData, serverProperty);
    }

    @Test
    void apk_key_hash_test() {
        Origin originA = new Origin("android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");
        Origin originB = new Origin("android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.CREATE, TestDataUtil.createChallenge(), originA, null);
        ServerProperty serverProperty = new ServerProperty(originB, "example.com", TestDataUtil.createChallenge(), null);
        target.validate(collectedClientData, serverProperty);
    }

    @Test
    void apk_key_hash_sha256_test() {
        Origin originA = new Origin("android:apk-key-hash-sha256:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");
        Origin originB = new Origin("android:apk-key-hash-sha256:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.CREATE, TestDataUtil.createChallenge(), originA, null);
        ServerProperty serverProperty = new ServerProperty(originB, "example.com", TestDataUtil.createChallenge(), null);
        target.validate(collectedClientData, serverProperty);
    }

    @Test
    void multiple_origins_test(){
        final Origin originA = new Origin("https://example.com:14443");
        final Origin originB = new Origin("http://localhost:9090");
        final Origin originC = new Origin("android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");
        final Origin originD = new Origin("android:apk-key-hash-sha256:qSiQ5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");

        final ServerProperty serverProperty = new ServerProperty(Arrays.asList(originA,originB,originC,originD),
                "example.com", TestDataUtil.createChallenge(), null);

        final CollectedClientData collectedClientDataA = new CollectedClientData(ClientDataType.CREATE,
                TestDataUtil.createChallenge(), originA, null);
        final CollectedClientData collectedClientDataB = new CollectedClientData(ClientDataType.CREATE,
                TestDataUtil.createChallenge(), originB, null);
        final CollectedClientData collectedClientDataC = new CollectedClientData(ClientDataType.GET,
                TestDataUtil.createChallenge(), originC, null);
        final CollectedClientData collectedClientDataD = new CollectedClientData(ClientDataType.GET,
                TestDataUtil.createChallenge(), originD, null);

        target.validate(collectedClientDataA,serverProperty);
        target.validate(collectedClientDataB,serverProperty);
        target.validate(collectedClientDataC,serverProperty);
        target.validate(collectedClientDataD,serverProperty);
    }

    @Test
    void multiple_origins_test_with_invalid_origin(){
        final Origin originA = new Origin("https://example.com:14443");
        final Origin originB = new Origin("http://localhost:9090");
        final Origin originC = new Origin("android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");
        final Origin originD = new Origin("android:apk-key-hash-sha256:qSiQ5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");

        final Origin badOriginA = new Origin("https://example.phish.com:14443");
        final Origin badOriginB = new Origin("http://phish.localhost:9090");
        final Origin badOriginC = new Origin("android:apk-key-hash:0pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");
        final Origin badOriginD = new Origin("android:apk-key-hash-sha256:0qSiQ5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");

        final ServerProperty serverProperty = new ServerProperty(Arrays.asList(originA,originB,originC,originD),
                "example.com", TestDataUtil.createChallenge(), null);

        final CollectedClientData collectedClientDataA = new CollectedClientData(ClientDataType.CREATE,
                TestDataUtil.createChallenge(), badOriginA, null);
        final CollectedClientData collectedClientDataB = new CollectedClientData(ClientDataType.CREATE,
                TestDataUtil.createChallenge(), badOriginB, null);
        final CollectedClientData collectedClientDataC = new CollectedClientData(ClientDataType.GET,
                TestDataUtil.createChallenge(), badOriginC, null);
        final CollectedClientData collectedClientDataD = new CollectedClientData(ClientDataType.GET,
                TestDataUtil.createChallenge(), badOriginD, null);


        assertThrows(BadOriginException.class,
                () -> target.validate(collectedClientDataA, serverProperty)
        );
        assertThrows(BadOriginException.class,
                () -> target.validate(collectedClientDataB, serverProperty)
        );
        assertThrows(BadOriginException.class,
                () -> target.validate(collectedClientDataC, serverProperty)
        );
        assertThrows(BadOriginException.class,
                () -> target.validate(collectedClientDataD, serverProperty)
        );
    }

    @Test
    void null_single_origin_input_test(){
        final Origin origin = new Origin("https://example.com:14443");

        final ServerProperty serverProperty = new ServerProperty((Origin)null,
                "example.com", TestDataUtil.createChallenge(), null);

        final CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.CREATE,
                TestDataUtil.createChallenge(), origin, null);


        assertThatExceptionOfType(IllegalStateException.class).isThrownBy(
                ()->target.validate(collectedClientData, serverProperty)
        ).withMessage("No origins configured for the given serverProperty");
    }

    @Test
    void null_multiple_origins_input_test(){
        final Origin origin = new Origin("https://example.com:14443");

        final ServerProperty serverProperty = new ServerProperty((Collection<Origin>)null,
                "example.com", TestDataUtil.createChallenge(), null);

        final CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.CREATE,
                TestDataUtil.createChallenge(), origin, null);


        assertThatExceptionOfType(IllegalStateException.class).isThrownBy(
                ()->target.validate(collectedClientData, serverProperty)
        ).withMessage("No origins configured for the given serverProperty");
    }

    @Test
    void empty_origins_input_test(){
        final Origin origin = new Origin("https://example.com:14443");

        final ServerProperty serverProperty = new ServerProperty(new ArrayList<>(),
                "example.com", TestDataUtil.createChallenge(), null);

        final CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.CREATE,
                TestDataUtil.createChallenge(), origin, null);


        assertThatExceptionOfType(IllegalStateException.class).isThrownBy(
                ()->target.validate(collectedClientData, serverProperty)
        ).withMessage("No origins configured for the given serverProperty");
    }

    @Test
    void validate_collected_client_data_having_null_origin_test(){
        final Origin origin = new Origin("https://example.com:14443");

        final ServerProperty serverProperty = new ServerProperty(Collections.singleton(origin),
                "example.com", TestDataUtil.createChallenge(), null);

        final CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.CREATE,
                TestDataUtil.createChallenge(), null, null);


        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(
                ()->target.validate(collectedClientData, serverProperty)
        ).withMessage("CollectedClientData has a null origin");
    }

    @Test
    void test_with_not_equal_origins() {
        Origin originA = new Origin("https://example.com:14443");
        Origin originB = new Origin("http://example.com");

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.CREATE, TestDataUtil.createChallenge(), originA, null);
        ServerProperty serverProperty = new ServerProperty(originB, "example.com", TestDataUtil.createChallenge(), null);
        assertThrows(BadOriginException.class,
                () -> target.validate(collectedClientData, serverProperty)
        );
    }

    @Test
    void apk_key_hash_test_with_not_equal_origins() {
        Origin originA = new Origin("android:apk-key-hash:aNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");
        Origin originB = new Origin("android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.CREATE, TestDataUtil.createChallenge(), originA, null);
        ServerProperty serverProperty = new ServerProperty(originB, "example.com", TestDataUtil.createChallenge(), null);
        assertThrows(BadOriginException.class,
                () -> target.validate(collectedClientData, serverProperty)
        );
    }

    @Test
    void apk_key_hash_sha256_test_with_not_equal_origins() {
        Origin originA = new Origin("android:apk-key-hash-sha256:aNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");
        Origin originB = new Origin("android:apk-key-hash-sha256:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.CREATE, TestDataUtil.createChallenge(), originA, null);
        ServerProperty serverProperty = new ServerProperty(originB, "example.com", TestDataUtil.createChallenge(), null);
        assertThrows(BadOriginException.class,
                () -> target.validate(collectedClientData, serverProperty)
        );
    }

    @Test
    void apk_key_hash_sha256_test_with_not_equal_origins_apk_key_hash_sha1() {
        Origin originA = new Origin("android:apk-key-hash-sha256:aNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");
        Origin originB = new Origin("android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.CREATE, TestDataUtil.createChallenge(), originA, null);
        ServerProperty serverProperty = new ServerProperty(originB, "example.com", TestDataUtil.createChallenge(), null);
        assertThrows(BadOriginException.class,
                () -> target.validate(collectedClientData, serverProperty)
        );
    }

    @Test
    void apk_key_hash_sha1_test_with_not_equal_origins_apk_key_hash_sha256() {
        Origin originA = new Origin("android:apk-key-hash:aNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");
        Origin originB = new Origin("android:apk-key-hash-sha256:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.CREATE, TestDataUtil.createChallenge(), originA, null);
        ServerProperty serverProperty = new ServerProperty(originB, "example.com", TestDataUtil.createChallenge(), null);
        assertThrows(BadOriginException.class,
                () -> target.validate(collectedClientData, serverProperty)
        );
    }

}
