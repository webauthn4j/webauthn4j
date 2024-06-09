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

package com.webauthn4j.verifier.attestation.statement.androidsafetynet;

import com.webauthn4j.data.attestation.statement.AndroidSafetyNetAttestationStatement;
import com.webauthn4j.data.attestation.statement.AttestationCertificate;
import com.webauthn4j.data.attestation.statement.AttestationType;
import com.webauthn4j.data.attestation.statement.Response;
import com.webauthn4j.data.jws.JWS;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.Base64Util;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.verifier.CoreRegistrationObject;
import com.webauthn4j.verifier.attestation.statement.AbstractStatementVerifier;
import com.webauthn4j.verifier.exception.BadAttestationStatementException;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

public class AndroidSafetyNetAttestationStatementVerifier extends AbstractStatementVerifier<AndroidSafetyNetAttestationStatement> {

    // ~ Instance fields
    // ================================================================================================

    private GooglePlayServiceVersionVerifier versionVerifier = new DefaultVersionVerifier();

    private int forwardThreshold = 0;
    private int backwardThreshold = 60;

    @SuppressWarnings("ConstantConditions")
    @Override
    public @NotNull AttestationType verify(@NotNull CoreRegistrationObject registrationObject) {

        AssertUtil.notNull(registrationObject, "registrationObject must not be null");

        if (!supports(registrationObject)) {
            throw new IllegalArgumentException("Specified format is not supported by " + this.getClass().getName());
        }

        AndroidSafetyNetAttestationStatement attestationStatement =
                (AndroidSafetyNetAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement();
        verifyAttestationStatementNotNull(attestationStatement);
        if (attestationStatement.getX5c().isEmpty()) {
            throw new BadAttestationStatementException("No attestation certificate is found in android safetynet attestation statement.");
        }

        /// Given the verification procedure inputs attStmt, authenticatorData and clientDataHash,
        //  the verification procedure is as follows:
        /// Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it
        //  to extract the contained fields.

        /// Verify that response is a valid SafetyNet response of version ver.
        versionVerifier.verify(attestationStatement.getVer());

        /// Verify that the nonce in the response is identical to the Base64url encoding of the SHA-256 hash of the concatenation of authenticatorData and clientDataHash.
        Response response = attestationStatement.getResponse().getPayload();
        String nonce = response.getNonce();
        byte[] authenticatorData = registrationObject.getAuthenticatorDataBytes();
        verifyNonce(nonce, authenticatorData, registrationObject.getClientDataHash());

        /// Let attestationCert be the attestation certificate.
        /// Verify that attestationCert is issued to the hostname "attest.android.com" (see SafetyNet online documentation).
        AttestationCertificate attestationCertificate = attestationStatement.getX5c().getEndEntityAttestationCertificate();
        if (!Objects.equals(attestationCertificate.getSubjectCommonName(), "attest.android.com")) {
            throw new BadAttestationStatementException("The attestation certificate is not issued to 'attest.android.com'.");
        }

        /// Verify that the ctsProfileMatch attribute in the payload of response is true.
        if (!Objects.equals(response.getCtsProfileMatch(), true)) {
            throw new BadAttestationStatementException("The profile of the device doesn't match the profile of a device that has passed Android Compatibility Test Suite.");
        }

        if (response.getTimestampMs() == null) {
            throw new BadAttestationStatementException("timestampMs is null.");
        }

        // Verify the timestampMs doesn't violate backwardThreshold
        if (Instant.ofEpochMilli(response.getTimestampMs()).isBefore(registrationObject.getTimestamp().minus(Duration.ofSeconds(backwardThreshold)))) {
            throw new BadAttestationStatementException("timestampMs violates backwardThreshold.");
        }

        // Verify the timestampMs doesn't violate forwardThreshold
        if (Instant.ofEpochMilli(response.getTimestampMs()).isAfter(registrationObject.getTimestamp().plus(Duration.ofSeconds(forwardThreshold)))) {
            throw new BadAttestationStatementException("timestampMs violates forwardThreshold.");
        }

        if (!attestationStatement.getResponse().isValidSignature()) {
            throw new BadAttestationStatementException("Android safetynet response in the attestation statement doesn't have a valid signature.");
        }

        /// If successful, return implementation-specific values representing attestation type Basic and attestation trust path attestationCert.
        return AttestationType.BASIC;
    }

    void verifyAttestationStatementNotNull(AndroidSafetyNetAttestationStatement attestationStatement) {
        if (attestationStatement == null) {
            throw new BadAttestationStatementException("attestation statement is not found.");
        }
        verifyJWSNotNull(attestationStatement.getResponse());
        if (attestationStatement.getX5c() == null) { //x5c is nullable here as x5c is extracted from header
            throw new BadAttestationStatementException("x5c must not be null");
        }
    }

    void verifyJWSNotNull(JWS<Response> response) {
        if (response == null) {
            throw new BadAttestationStatementException("response must not be null.");
        }
        verifyResponseNotNull(response.getPayload());
    }

    void verifyResponseNotNull(Response response) {
        if (response == null) {
            throw new BadAttestationStatementException("response must not be null.");
        }
        if (response.getNonce() == null) {
            throw new BadAttestationStatementException("nonce must not be null.");
        }
        if (response.getTimestampMs() == null) {
            throw new BadAttestationStatementException("timeStampMs must not be null.");
        }
        if (response.getApkPackageName() == null) {
            throw new BadAttestationStatementException("apkPackageName must not be null.");
        }
        if (response.getApkCertificateDigestSha256() == null) {
            throw new BadAttestationStatementException("apkCertificateDigestSha256 must not be null.");
        }
        if (response.getApkDigestSha256() == null) {
            throw new BadAttestationStatementException("apkDigestSha256 must not be null.");
        }
        if (response.getCtsProfileMatch() == null) {
            throw new BadAttestationStatementException("ctsProfileMatch must not be null.");
        }
        if (response.getBasicIntegrity() == null) {
            throw new BadAttestationStatementException("basicIntegrity must not be null.");
        }
    }

    private void verifyNonce(@Nullable String nonce, @NotNull byte[] authenticatorData, @NotNull byte[] clientDataHash) {
        if (nonce == null) {
            throw new BadAttestationStatementException("Nonce in the Android safetynet response is null.");
        }
        ByteBuffer buffer = ByteBuffer.allocate(authenticatorData.length + clientDataHash.length);
        byte[] data = buffer.put(authenticatorData).put(clientDataHash).array();
        byte[] hash = MessageDigestUtil.createSHA256().digest(data);
        // As nonce is known data to client side(potential attacker) because it is calculated from parts of a message,
        // there is no need to prevent timing attack and it is OK to use `Arrays.equals` instead of `MessageDigest.isEqual` here.
        if (!Arrays.equals(hash, Base64Util.decode(nonce))) {
            throw new BadAttestationStatementException("Nonce in the Android safetynet response doesn't match.");
        }
    }

    public int getForwardThreshold() {
        return forwardThreshold;
    }

    public void setForwardThreshold(int forwardThreshold) {
        this.forwardThreshold = forwardThreshold;
    }

    public int getBackwardThreshold() {
        return backwardThreshold;
    }

    public void setBackwardThreshold(int backwardThreshold) {
        this.backwardThreshold = backwardThreshold;
    }

    public @NotNull GooglePlayServiceVersionVerifier getVersionVerifier() {
        return versionVerifier;
    }

    public void setVersionVerifier(@NotNull GooglePlayServiceVersionVerifier versionVerifier) {
        AssertUtil.notNull(versionVerifier, "versionVerifier must not be null");
        this.versionVerifier = versionVerifier;
    }

    private static class DefaultVersionVerifier implements GooglePlayServiceVersionVerifier {

        private static final int MINIMAL_VERSION = 0;

        @Override
        public void verify(@NotNull String version) {
            try {
                int versionNumber = Integer.parseInt(version);
                if (versionNumber < MINIMAL_VERSION) {
                    throw new BadAttestationStatementException("The version number of Google Play Services responsible for providing the SafetyNet API doesn't conform minimal requirement.");
                }
            } catch (NumberFormatException e) {
                throw new BadAttestationStatementException("`ver` in android safetynet attestation statement cannot be parsed as number.");
            }
        }
    }
}
