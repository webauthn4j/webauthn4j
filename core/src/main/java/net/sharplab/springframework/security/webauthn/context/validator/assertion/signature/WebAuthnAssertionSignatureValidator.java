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

package net.sharplab.springframework.security.webauthn.context.validator.assertion.signature;

import net.sharplab.springframework.security.webauthn.context.WebAuthnAuthenticationContext;
import net.sharplab.springframework.security.webauthn.util.MessageDigestUtil;

import java.nio.ByteBuffer;
import java.security.MessageDigest;

/**
 * WebAuthnAssertionSignatureValidator
 */
public class WebAuthnAssertionSignatureValidator extends AbstractAssertionSignatureValidator {

    @Override
    public boolean supports(String format) {
        return !"fido-u2f".equals(format);
    }

    protected byte[] getSignedData(WebAuthnAuthenticationContext webAuthnAuthenticationContext){
        String hashAlgorithm = webAuthnAuthenticationContext.getCollectedClientData().getHashAlgorithm();
        MessageDigest messageDigest = MessageDigestUtil.createMessageDigest(hashAlgorithm);
        byte[] clientDataHash = messageDigest.digest(webAuthnAuthenticationContext.getRawClientData());
        byte[] rawAuthenticatorData= webAuthnAuthenticationContext.getRawAuthenticatorData();
        return ByteBuffer.allocate(rawAuthenticatorData.length + clientDataHash.length).put(rawAuthenticatorData).put(clientDataHash).array();
    }


}
