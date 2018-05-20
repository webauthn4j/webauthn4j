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
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.validator.exception.BadRpIdException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Validates rpIdHash
 */
class RpIdHashValidator {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    public void validate(byte[] rpIdHash, ServerProperty serverProperty) {
        AssertUtil.notNull(serverProperty, "serverProperty must not be null");
        String rpId = serverProperty.getRpId();
        AssertUtil.notNull(rpId, "serverProperty must not be null");

        MessageDigest messageDigest = MessageDigestUtil.createSHA256();
        byte[] relyingPartyRpIdBytes = rpId.getBytes(StandardCharsets.UTF_8);
        byte[] relyingPartyRpIdHash = messageDigest.digest(relyingPartyRpIdBytes);
        if (!Arrays.equals(rpIdHash, relyingPartyRpIdHash)) {
            logger.debug("Authentication failed: bad rpId is specified");
            throw new BadRpIdException("Bad rpId");
        }
    }
}
