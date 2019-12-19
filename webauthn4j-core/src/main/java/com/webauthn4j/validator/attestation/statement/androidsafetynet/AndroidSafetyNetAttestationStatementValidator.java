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

package com.webauthn4j.validator.attestation.statement.androidsafetynet;

import com.webauthn4j.data.attestation.statement.AndroidSafetyNetAttestationStatement;
import com.webauthn4j.data.attestation.statement.AttestationCertificate;
import com.webauthn4j.data.attestation.statement.AttestationType;
import com.webauthn4j.data.attestation.statement.Response;
import com.webauthn4j.util.Base64Util;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.validator.RegistrationObject;
import com.webauthn4j.validator.attestation.statement.AbstractStatementValidator;
import com.webauthn4j.validator.exception.BadAttestationStatementException;

import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Objects;

public class AndroidSafetyNetAttestationStatementValidator extends AbstractStatementValidator<AndroidSafetyNetAttestationStatement> {

    // ~ Instance fields
    // ================================================================================================

    private GooglePlayServiceVersionValidator versionValidator = new DefaultVersionValidator();

    private int forwardThreshold = 0;
    private int backwardThreshold = 60;

    @Override
    public AttestationType validate(RegistrationObject registrationObject) {
        if (!supports(registrationObject)) {
            throw new IllegalArgumentException("Specified format is not supported by " + this.getClass().getName());
        }

        AndroidSafetyNetAttestationStatement attestationStatement =
                (AndroidSafetyNetAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement();

        if (attestationStatement.getX5c().isEmpty()) {
            throw new BadAttestationStatementException("No attestation certificate is found in android safetynet attestation statement.");
        }

        /// Given the verification procedure inputs attStmt, authenticatorData and clientDataHash,
        //  the verification procedure is as follows:
        /// Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it
        //  to extract the contained fields.

        /// Verify that response is a valid SafetyNet response of version ver.
        versionValidator.validate(attestationStatement.getVer());

        /// Verify that the nonce in the response is identical to the Base64url encoding of the SHA-256 hash of the concatenation of authenticatorData and clientDataHash.
        Response response = attestationStatement.getResponse().getPayload();
        String nonce = response.getNonce();
        byte[] authenticatorData = registrationObject.getAuthenticatorDataBytes();
        byte[] collectedClientData = registrationObject.getCollectedClientDataBytes();
        validateNonce(nonce, authenticatorData, collectedClientData);

        /// Let attestationCert be the attestation certificate.
        /// Verify that attestationCert is issued to the hostname "attest.android.com" (see SafetyNet online documentation).
        AttestationCertificate attestationCertificate = attestationStatement.getX5c().getEndEntityAttestationCertificate();
        if (!Objects.equals(attestationCertificate.getSubjectCommonName(), "attest.android.com")) {
            throw new BadAttestationStatementException("The attestation certificate is not issued to 'attest.android.com'.");
        }

        /// Verify that the ctsProfileMatch attribute in the payload of response is true.
        if (!response.isCtsProfileMatch()) {
            throw new BadAttestationStatementException("The profile of the device doesn't match the profile of a device that has passed Android Compatibility Test Suite.");
        }

        // Verify the timestampMs doesn't violate backwardThreshold
        if (Instant.ofEpochMilli(response.getTimestampMs()).isBefore(registrationObject.getTimestamp().toInstant(ZoneOffset.UTC).minus(Duration.ofSeconds(backwardThreshold)))) {
            throw new BadAttestationStatementException("timestampMs violates backwardThreshold.");
        }

        // Verify the timestampMs doesn't violate forwardThreshold
        if (Instant.ofEpochMilli(response.getTimestampMs()).isAfter(registrationObject.getTimestamp().toInstant(ZoneOffset.UTC).plus(Duration.ofSeconds(forwardThreshold)))) {
            throw new BadAttestationStatementException("timestampMs violates forwardThreshold.");
        }

        if (!attestationStatement.getResponse().isValidSignature()) {
            throw new BadAttestationStatementException("Android safetynet response in the attestation statement doesn't have a valid signature.");
        }

        /// If successful, return implementation-specific values representing attestation type Basic and attestation trust path attestationCert.
        return AttestationType.BASIC;
    }

    private void validateNonce(String nonce, byte[] authenticatorData, byte[] collectedClientData) {
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(collectedClientData);
        ByteBuffer buffer = ByteBuffer.allocate(authenticatorData.length + clientDataHash.length);
        byte[] data = buffer.put(authenticatorData).put(clientDataHash).array();
        byte[] hash = MessageDigestUtil.createSHA256().digest(data);
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

    public GooglePlayServiceVersionValidator getVersionValidator() {
        return versionValidator;
    }

    public void setVersionValidator(GooglePlayServiceVersionValidator versionValidator) {
        this.versionValidator = versionValidator;
    }

    private class DefaultVersionValidator implements GooglePlayServiceVersionValidator {

        private int minimalVersion = 0;

        @Override
        public void validate(String version) {
            try {
                int versionNumber = Integer.parseInt(version);
                if (versionNumber < minimalVersion) {
                    throw new BadAttestationStatementException("The version number of Google Play Services responsible for providing the SafetyNet API doesn't conform minimal requirement.");
                }
            } catch (NumberFormatException e) {
                throw new BadAttestationStatementException("`ver` in android safetynet attestation statement cannot be parsed as number.");
            }
        }
    }
}
