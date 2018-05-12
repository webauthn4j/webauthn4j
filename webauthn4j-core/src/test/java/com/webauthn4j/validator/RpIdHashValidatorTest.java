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

import com.webauthn4j.rp.RelyingParty;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.validator.exception.BadRpIdException;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

/**
 * Created by ynojima on 2017/08/27.
 */
public class RpIdHashValidatorTest {

    private RpIdHashValidator target = new RpIdHashValidator();

    @Test
    public void verifyRpIdHash_test() {

        String rpIdA = "example.com";
        String rpIdB = "example.com";
        byte[] rpIdBytesA = rpIdA.getBytes(StandardCharsets.UTF_8);
        byte[] rpIdHashA = MessageDigestUtil.createSHA256().digest(rpIdBytesA);

        RelyingParty relyingParty = new RelyingParty(null, rpIdB, null);

        //When
        target.validate(rpIdHashA, relyingParty);
    }

    @Test(expected = BadRpIdException.class)
    public void verifyRpIdHash_test_with_different_rpIds() {

        String rpIdA = "sub.example.com";
        String rpIdB = "example.com";
        byte[] rpIdBytesA = rpIdA.getBytes(StandardCharsets.UTF_8);
        byte[] rpIdHashA = MessageDigestUtil.createSHA256().digest(rpIdBytesA);

        RelyingParty relyingParty = new RelyingParty(null, rpIdB, null);

        //When
        target.validate(rpIdHashA, relyingParty);
    }

}
