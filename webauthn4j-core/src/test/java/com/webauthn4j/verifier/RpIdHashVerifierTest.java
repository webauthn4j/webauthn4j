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

import com.webauthn4j.data.client.Origin;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.verifier.exception.BadRpIdException;
import com.webauthn4j.verifier.internal.RpIdHashVerifier;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Created by ynojima on 2017/08/27.
 */
@SuppressWarnings("ConstantConditions")
class RpIdHashVerifierTest {

    private final Origin origin = Origin.create("https://example.com");

    @Test
    void verify_test() {

        String rpIdA = "example.com";
        String rpIdB = "example.com";
        byte[] rpIdBytesA = rpIdA.getBytes(StandardCharsets.UTF_8);
        byte[] rpIdHashA = MessageDigestUtil.createSHA256().digest(rpIdBytesA);

        ServerProperty serverProperty = new ServerProperty(origin, rpIdB, null, null);

        //When
        RpIdHashVerifier.verify(rpIdHashA, serverProperty);
    }

    @Test
    void verify_test_with_different_rpIds() {

        String rpIdA = "sub.example.com";
        String rpIdB = "example.com";
        byte[] rpIdBytesA = rpIdA.getBytes(StandardCharsets.UTF_8);
        byte[] rpIdHashA = MessageDigestUtil.createSHA256().digest(rpIdBytesA);

        ServerProperty serverProperty = new ServerProperty(origin, rpIdB, null, null);

        //When
        assertThrows(BadRpIdException.class,
                () -> RpIdHashVerifier.verify(rpIdHashA, serverProperty)
        );
    }

    @Test
    void verify_test_with_relyingParty_null() {

        String rpIdA = "example.com";
        byte[] rpIdBytesA = rpIdA.getBytes(StandardCharsets.UTF_8);
        byte[] rpIdHashA = MessageDigestUtil.createSHA256().digest(rpIdBytesA);

        //When
        assertThrows(IllegalArgumentException.class,
                () -> RpIdHashVerifier.verify(rpIdHashA, null)
        );
    }

}
