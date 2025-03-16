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

package com.webauthn4j.verifier.internal;

import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.CoreAuthenticationData;
import com.webauthn4j.data.SignatureAlgorithm;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.SignatureUtil;
import com.webauthn4j.verifier.exception.BadSignatureException;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.security.*;

/**
 * Verifies the assertion signature in {@link AuthenticationData} based on {@link COSEKey}
 */
public class AssertionSignatureVerifier {

    private final Logger logger = LoggerFactory.getLogger(AssertionSignatureVerifier.class);

    // ~ Methods
    // ========================================================================================================

    public void verify(@NotNull CoreAuthenticationData authenticationData, @NotNull COSEKey coseKey) {
        AssertUtil.notNull(authenticationData, "authenticationData must not be null");
        AssertUtil.notNull(coseKey, "coseKey must not be null");

        byte[] signedData = getSignedData(authenticationData);
        byte[] signature = authenticationData.getSignature();
        if (!verifySignature(coseKey, signature, signedData)) {
            throw new BadSignatureException("Assertion signature is not valid.");
        }
    }

    protected @NotNull byte[] getSignedData(@NotNull CoreAuthenticationData authenticationData) {
        byte[] rawAuthenticatorData = authenticationData.getAuthenticatorDataBytes();
        byte[] clientDataHash = authenticationData.getClientDataHash();
        return ByteBuffer.allocate(rawAuthenticatorData.length + clientDataHash.length).put(rawAuthenticatorData).put(clientDataHash).array();
    }

    private boolean verifySignature(@NotNull COSEKey coseKey, @NotNull byte[] signature, @NotNull byte[] data) {
        try {
            PublicKey publicKey = coseKey.getPublicKey();
            //noinspection ConstantConditions as null check is already done in caller
            SignatureAlgorithm signatureAlgorithm = coseKey.getAlgorithm().toSignatureAlgorithm();
            Signature verifier = SignatureUtil.createSignature(signatureAlgorithm);
            verifier.initVerify(publicKey);
            verifier.update(data);
            return verifier.verify(signature);
        } catch (IllegalArgumentException e) {
            logger.debug("COSE key alg must be signature algorithm.", e);
            return false;
        } catch (SignatureException | InvalidKeyException | RuntimeException e) {
            logger.debug("Unexpected exception is thrown during signature verification.", e);
            return false;
        }
    }


}
