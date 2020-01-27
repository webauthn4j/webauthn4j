/*
 * Copyright 2018 the original author or authors.
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

import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.statement.SignatureAlgorithm;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.validator.exception.BadSignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.security.*;

/**
 * Validates the assertion signature in {@link AuthenticationData} based on {@link COSEKey}
 */
class AssertionSignatureValidator {

    Logger logger = LoggerFactory.getLogger(AssertionSignatureValidator.class);

    // ~ Methods
    // ========================================================================================================

    public void validate(AuthenticationData authenticationData, COSEKey coseKey) {
        byte[] signedData = getSignedData(authenticationData);
        byte[] signature = authenticationData.getSignature();
        if (!verifySignature(coseKey, signature, signedData)) {
            throw new BadSignatureException("Assertion signature is not valid.");
        }
    }

    private byte[] getSignedData(AuthenticationData authenticationData) {
        MessageDigest messageDigest = MessageDigestUtil.createSHA256();
        byte[] rawAuthenticatorData = authenticationData.getAuthenticatorDataBytes();
        byte[] clientDataHash = messageDigest.digest(authenticationData.getCollectedClientDataBytes());
        return ByteBuffer.allocate(rawAuthenticatorData.length + clientDataHash.length).put(rawAuthenticatorData).put(clientDataHash).array();
    }

    private boolean verifySignature(COSEKey coseKey, byte[] signature, byte[] data) {
        try {
            PublicKey publicKey = coseKey.getPublicKey();
            SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.create(coseKey.getAlgorithm());
            String jcaName = signatureAlgorithm.getJcaName();
            Signature verifier = Signature.getInstance(jcaName);
            verifier.initVerify(publicKey);
            verifier.update(data);
            return verifier.verify(signature);
        } catch (IllegalArgumentException e) {
            logger.debug("COSE key alg must be signature algorithm.", e);
            return false;
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | RuntimeException e) {
            logger.debug("Unexpected exception is thrown during signature verification.", e);
            return false;
        }
    }


}
