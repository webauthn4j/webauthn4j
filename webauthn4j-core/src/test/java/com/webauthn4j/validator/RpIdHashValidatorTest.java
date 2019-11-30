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

package com.webauthn4j.validator;

import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.validator.exception.BadRpIdException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

/**
 * Created by ynojima on 2017/08/27.
 */
class RpIdHashValidatorTest {

    private RpIdHashValidator target = new RpIdHashValidator();

    @Test
    void verifyRpIdHash_test() {

        RegistrationObject registrationObject = mock(RegistrationObject.class);

        String rpIdA = "example.com";
        String rpIdB = "example.com";
        byte[] rpIdBytesA = rpIdA.getBytes(StandardCharsets.UTF_8);
        byte[] rpIdHashA = MessageDigestUtil.createSHA256().digest(rpIdBytesA);

        ServerProperty serverProperty = new ServerProperty(null, rpIdB, null, null);

        //When
        target.validate(registrationObject, rpIdHashA, serverProperty);
    }

    @Test
    void verifyRpIdHash_test_with_different_rpIds() {

        RegistrationObject registrationObject = mock(RegistrationObject.class);

        String rpIdA = "sub.example.com";
        String rpIdB = "example.com";
        byte[] rpIdBytesA = rpIdA.getBytes(StandardCharsets.UTF_8);
        byte[] rpIdHashA = MessageDigestUtil.createSHA256().digest(rpIdBytesA);

        ServerProperty serverProperty = new ServerProperty(null, rpIdB, null, null);

        //When
        assertThrows(BadRpIdException.class,
                () -> target.validate(registrationObject, rpIdHashA, serverProperty)
        );
    }

    @Test
    void verifyRpIdHash_test_with_relyingParty_null() {

        RegistrationObject registrationObject = mock(RegistrationObject.class);

        String rpIdA = "example.com";
        String rpIdB = "example.com";
        byte[] rpIdBytesA = rpIdA.getBytes(StandardCharsets.UTF_8);
        byte[] rpIdHashA = MessageDigestUtil.createSHA256().digest(rpIdBytesA);

        //When
        assertThrows(IllegalArgumentException.class,
                () -> target.validate(registrationObject, rpIdHashA, null)
        );
    }

    @Test
    void verifyRpIdHash_test_with_relyingParty_rpId_null() {

        RegistrationObject registrationObject = mock(RegistrationObject.class);

        String rpIdA = "example.com";
        String rpIdB = "example.com";
        byte[] rpIdBytesA = rpIdA.getBytes(StandardCharsets.UTF_8);
        byte[] rpIdHashA = MessageDigestUtil.createSHA256().digest(rpIdBytesA);

        ServerProperty serverProperty = new ServerProperty(null, null, null, null);

        //When
        assertThrows(IllegalArgumentException.class,
                () -> target.validate(registrationObject, rpIdHashA, serverProperty)
        );
    }
}
