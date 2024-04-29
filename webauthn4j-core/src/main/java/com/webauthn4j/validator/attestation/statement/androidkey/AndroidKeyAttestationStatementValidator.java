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

package com.webauthn4j.validator.attestation.statement.androidkey;

import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.AndroidKeyAttestationStatement;
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.data.attestation.statement.AttestationType;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.SignatureUtil;
import com.webauthn4j.validator.CoreRegistrationObject;
import com.webauthn4j.validator.attestation.statement.AbstractStatementValidator;
import com.webauthn4j.validator.exception.BadAttestationStatementException;
import com.webauthn4j.validator.exception.BadSignatureException;
import com.webauthn4j.validator.exception.PublicKeyMismatchException;
import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;

public class AndroidKeyAttestationStatementValidator extends AbstractStatementValidator<AndroidKeyAttestationStatement> {

    // ~ Instance fields
    // ================================================================================================

    private final KeyDescriptionValidator keyDescriptionValidator = new KeyDescriptionValidator();
    private boolean teeEnforcedOnly = true;

    @Override
    public @NotNull AttestationType validate(@NotNull CoreRegistrationObject registrationObject) {
        AssertUtil.notNull(registrationObject, "registrationObject must not be null");

        if (!supports(registrationObject)) {
            throw new IllegalArgumentException(String.format("Specified format '%s' is not supported by %s.", registrationObject.getAttestationObject().getFormat(), this.getClass().getName()));
        }

        AndroidKeyAttestationStatement attestationStatement =
                (AndroidKeyAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement();

        validateAttestationStatementNotNull(attestationStatement);

        if (attestationStatement.getX5c().isEmpty()) {
            throw new BadAttestationStatementException("No attestation certificate is found in android key attestation statement.");
        }

        /// Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.

        /// Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the public key in the first certificate in x5c with the algorithm specified in alg.
        validateSignature(registrationObject);

        /// Verify that the public key in the first certificate in x5c matches the credentialPublicKey in the attestedCredentialData in authenticatorData.
        PublicKey publicKeyInEndEntityCert = attestationStatement.getX5c().getEndEntityAttestationCertificate().getCertificate().getPublicKey();
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = registrationObject.getAttestationObject().getAuthenticatorData();
        //noinspection ConstantConditions as null check is already done in caller
        PublicKey publicKeyInCredentialData = authenticatorData.getAttestedCredentialData().getCOSEKey().getPublicKey();
        if (!publicKeyInEndEntityCert.equals(publicKeyInCredentialData)) {
            throw new PublicKeyMismatchException("The public key in the first certificate in x5c doesn't matches the credentialPublicKey in the attestedCredentialData in authenticatorData.");
        }

        byte[] clientDataHash = registrationObject.getClientDataHash();
        keyDescriptionValidator.validate(attestationStatement.getX5c().getEndEntityAttestationCertificate().getCertificate(), clientDataHash, teeEnforcedOnly);

        return AttestationType.BASIC;
    }

    void validateAttestationStatementNotNull(AndroidKeyAttestationStatement attestationStatement) {
        if (attestationStatement == null) {
            throw new BadAttestationStatementException("attestation statement is not found.");
        }
    }

    private void validateSignature(@NotNull CoreRegistrationObject registrationObject) {
        AndroidKeyAttestationStatement attestationStatement = (AndroidKeyAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement();

        byte[] signedData = getSignedData(registrationObject);
        byte[] signature = attestationStatement.getSig();
        PublicKey publicKey = getPublicKey(attestationStatement);

        try {
            String jcaName;
            jcaName = getJcaName(attestationStatement.getAlg());
            Signature verifier = SignatureUtil.createSignature(jcaName);
            verifier.initVerify(publicKey);
            verifier.update(signedData);
            if (verifier.verify(signature)) {
                return;
            }
            throw new BadSignatureException("`sig` in attestation statement is not valid signature over the concatenation of authenticatorData and clientDataHash.");
        } catch (SignatureException | InvalidKeyException e) {
            throw new BadSignatureException("`sig` in attestation statement is not valid signature over the concatenation of authenticatorData and clientDataHash.", e);
        }
    }

    private @NotNull byte[] getSignedData(@NotNull CoreRegistrationObject registrationObject) {
        byte[] authenticatorData = registrationObject.getAuthenticatorDataBytes();
        byte[] clientDataHash = registrationObject.getClientDataHash();
        return ByteBuffer.allocate(authenticatorData.length + clientDataHash.length).put(authenticatorData).put(clientDataHash).array();
    }

    private @NotNull PublicKey getPublicKey(@NotNull AndroidKeyAttestationStatement attestationStatement) {
        AttestationCertificatePath x5c = attestationStatement.getX5c();
        Certificate cert = x5c.getEndEntityAttestationCertificate().getCertificate();
        return cert.getPublicKey();
    }

    public boolean isTeeEnforcedOnly() {
        return teeEnforcedOnly;
    }

    public void setTeeEnforcedOnly(boolean teeEnforcedOnly) {
        this.teeEnforcedOnly = teeEnforcedOnly;
    }
}
