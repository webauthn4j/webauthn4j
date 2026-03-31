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

package com.webauthn4j.verifier.attestation.statement.apple;

import com.webauthn4j.data.attestation.statement.AppleAnonymousAttestationStatement;
import com.webauthn4j.data.attestation.statement.AttestationType;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.verifier.CoreRegistrationObject;
import com.webauthn4j.verifier.attestation.statement.AbstractStatementVerifier;
import com.webauthn4j.verifier.exception.BadAttestationStatementException;
import com.webauthn4j.verifier.exception.PublicKeyMismatchException;
import com.webauthn4j.verifier.internal.asn1.ASN1Primitive;
import com.webauthn4j.verifier.internal.asn1.ASN1Structure;
import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * Verifies the specified {@link AppleAnonymousAttestationStatement} is a valid Apple Anonymous attestation
 * according to WebAuthn Level 3 specification.
 * <p>
 * Implements the verification procedure defined in:
 * <a href="https://www.w3.org/TR/webauthn-3/#sctn-apple-anonymous-attestation">
 * WebAuthn Level 3 § 8.8 Apple Anonymous Attestation Statement Format</a>
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/">Web Authentication: An API for accessing Public Key Credentials - Level 3</a>
 */
public class AppleAnonymousAttestationStatementVerifier extends AbstractStatementVerifier<AppleAnonymousAttestationStatement> {

    // ~ Instance fields
    // ================================================================================================


    @Override
    public @NotNull AttestationType verify(@NotNull CoreRegistrationObject registrationObject) {
        AssertUtil.notNull(registrationObject, "registrationObject must not be null");
        if (!supports(registrationObject)) {
            throw new IllegalArgumentException(String.format("Specified format '%s' is not supported by %s.", registrationObject.getAttestationObject().getFormat(), this.getClass().getName()));
        }

        AppleAnonymousAttestationStatement attestationStatement =
                (AppleAnonymousAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement();
        verifyAttestationStatementNotNull(attestationStatement);
        //spec| Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
        //spec| Concatenate authenticatorData and clientDataHash to form nonceToHash.
        //spec| Perform SHA-256 hash of nonceToHash to produce nonce.
        //spec| Verify that nonce equals the value of the extension with OID 1.2.840.113635.100.8.2 in credCert.
        verifyNonce(registrationObject);

        //spec| Verify that the credential public key equals the Subject Public Key of credCert.
        verifyPublicKey(registrationObject, attestationStatement);

        //spec| If successful, return implementation-specific values representing attestation type Anonymization CA and attestation trust path x5c.
        return AttestationType.BASIC;
    }

    void verifyAttestationStatementNotNull(AppleAnonymousAttestationStatement attestationStatement) {
        if (attestationStatement == null) {
            throw new BadAttestationStatementException("attestation statement is not found.");
        }
    }

    private void verifyNonce(@NotNull CoreRegistrationObject registrationObject) {
        AppleAnonymousAttestationStatement attestationStatement = (AppleAnonymousAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement();

        byte[] nonce = getNonce(registrationObject);
        byte[] extracted = extractNonce(attestationStatement.getX5c().getEndEntityAttestationCertificate().getCertificate());

        // As nonce is known data to client side(potential attacker) because it is calculated from parts of a message,
        // there is no need to prevent timing attack and it is OK to use `Arrays.equals` instead of `MessageDigest.isEqual` here.
        if (!Arrays.equals(extracted, nonce)) {
            throw new BadAttestationStatementException("nonce doesn't match.");
        }
    }

    private @NotNull byte[] getNonce(@NotNull CoreRegistrationObject registrationObject) {
        byte[] authenticatorData = registrationObject.getAuthenticatorDataBytes();
        byte[] clientDataHash = registrationObject.getClientDataHash();
        byte[] nonceToHash = ByteBuffer.allocate(authenticatorData.length + clientDataHash.length).put(authenticatorData).put(clientDataHash).array();
        return MessageDigestUtil.createSHA256().digest(nonceToHash);
    }

    private void verifyPublicKey(@NotNull CoreRegistrationObject registrationObject, @NotNull AppleAnonymousAttestationStatement attestationStatement) {
        PublicKey publicKeyInEndEntityCert = attestationStatement.getX5c().getEndEntityAttestationCertificate().getCertificate().getPublicKey();
        //noinspection ConstantConditions as null check is already done in caller.
        PublicKey publicKeyInCredentialData = registrationObject.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getCOSEKey().getPublicKey();
        if (!publicKeyInEndEntityCert.equals(publicKeyInCredentialData)) {
            throw new PublicKeyMismatchException("The public key in the first certificate in x5c doesn't matches the credentialPublicKey in the attestedCredentialData in authenticatorData.");
        }
    }

    private byte[] extractNonce(X509Certificate attestationCertificate) {
        byte[] extensionValue = attestationCertificate.getExtensionValue("1.2.840.113635.100.8.2");
        if (extensionValue == null) {
            throw new BadAttestationStatementException("Apple X.509 extension not found");
        }

        try {
            ASN1Primitive extensionEnvelope = ASN1Primitive.parse(extensionValue);
            ASN1Structure sequence = extensionEnvelope.getValueAsASN1Structure();
            ASN1Structure innerSequence = (ASN1Structure) sequence.get(0);
            ASN1Primitive firstItem = (ASN1Primitive) innerSequence.get(0);
            return firstItem.getValue();
        } catch (RuntimeException e) {
            throw new BadAttestationStatementException("Failed to extract nonce from Apple anonymous attestation statement.", e);
        }
    }

}