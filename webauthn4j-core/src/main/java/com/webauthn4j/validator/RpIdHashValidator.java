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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Validates the specified rpIdHash
 */
class RpIdHashValidator {

    //~ Instance fields
    // ================================================================================================


    // ~ Methods
    // ========================================================================================================
    void validate(RegistrationObject registrationObject, byte[] rpIdHash, ServerProperty serverProperty){
        validate(registrationObject, null, rpIdHash, serverProperty);
    }

    void validate(AuthenticationObject authenticationObject, byte[] rpIdHash, ServerProperty serverProperty) {
        validate(null, authenticationObject, rpIdHash, serverProperty);
    }

    private void validate(RegistrationObject registrationObject, AuthenticationObject authenticationObject,
                          byte[] rpIdHash, ServerProperty serverProperty) {
        AssertUtil.notNull(serverProperty, "serverProperty must not be null");
        String rpId = serverProperty.getRpId();
        AssertUtil.notNull(rpId, "rpId must not be null");

        MessageDigest messageDigest = MessageDigestUtil.createSHA256();
        byte[] relyingPartyRpIdBytes = rpId.getBytes(StandardCharsets.UTF_8);
        byte[] relyingPartyRpIdHash = messageDigest.digest(relyingPartyRpIdBytes);
        if (!Arrays.equals(rpIdHash, relyingPartyRpIdHash)) {
            throw new BadRpIdException("rpIdHash doesn't match the hash of preconfigured rpId.", registrationObject, authenticationObject);
        }
    }
}
