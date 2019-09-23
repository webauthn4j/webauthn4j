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

import com.webauthn4j.data.WebAuthnAuthenticationContext;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.validator.exception.BadSignatureException;

import java.nio.ByteBuffer;
import java.security.*;

/**
 * Validates the assertion signature in {@link WebAuthnAuthenticationContext} based on {@link COSEKey}
 */
class AssertionSignatureValidator {

    // ~ Methods
    // ========================================================================================================

    public void validate(WebAuthnAuthenticationContext webAuthnAuthenticationContext, COSEKey coseKey) {
        byte[] signedData = getSignedData(webAuthnAuthenticationContext);
        byte[] signature = webAuthnAuthenticationContext.getSignature();
        if (!verifySignature(coseKey, signature, signedData)) {
            throw new BadSignatureException("Assertion signature is not valid.");
        }
    }

    private byte[] getSignedData(WebAuthnAuthenticationContext webAuthnAuthenticationContext) {
        MessageDigest messageDigest = MessageDigestUtil.createSHA256();
        byte[] rawAuthenticatorData = webAuthnAuthenticationContext.getAuthenticatorData();
        byte[] clientDataHash = messageDigest.digest(webAuthnAuthenticationContext.getClientDataJSON());
        return ByteBuffer.allocate(rawAuthenticatorData.length + clientDataHash.length).put(rawAuthenticatorData).put(clientDataHash).array();
    }

    private boolean verifySignature(COSEKey coseKey, byte[] signature, byte[] data) {
        try {
            PublicKey publicKey = coseKey.getPublicKey();
            Signature verifier = Signature.getInstance(coseKey.getAlgorithm().getJcaName());
            verifier.initVerify(publicKey);
            verifier.update(data);

            return verifier.verify(signature);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | RuntimeException e) {
            return false;
        }
    }


}
