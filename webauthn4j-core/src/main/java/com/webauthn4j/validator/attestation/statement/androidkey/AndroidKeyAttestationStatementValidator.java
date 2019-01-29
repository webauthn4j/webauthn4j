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

package com.webauthn4j.validator.attestation.statement.androidkey;

import com.webauthn4j.response.attestation.statement.AndroidKeyAttestationStatement;
import com.webauthn4j.response.attestation.statement.AttestationStatement;
import com.webauthn4j.response.attestation.statement.AttestationType;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.util.SignatureUtil;
import com.webauthn4j.validator.RegistrationObject;
import com.webauthn4j.validator.attestation.statement.AttestationStatementValidator;
import com.webauthn4j.validator.exception.BadAttestationStatementException;
import com.webauthn4j.validator.exception.BadSignatureException;
import com.webauthn4j.validator.exception.PublicKeyMismatchException;
import com.webauthn4j.validator.exception.UnsupportedAttestationFormatException;

import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.Certificate;

public class AndroidKeyAttestationStatementValidator implements AttestationStatementValidator {

    // ~ Instance fields
    // ================================================================================================

    private KeyDescriptionValidator keyDescriptionValidator = new KeyDescriptionValidator();
    private boolean teeEnforcedOnly = true;

    @Override
    public AttestationType validate(RegistrationObject registrationObject) {
        if (!supports(registrationObject)) {
            throw new UnsupportedAttestationFormatException("Specified format is not supported by " + this.getClass().getName());
        }

        AndroidKeyAttestationStatement attestationStatement =
                (AndroidKeyAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement();

        if (attestationStatement.getX5c().isEmpty()) {
            throw new BadAttestationStatementException("No attestation certificate is found'.");
        }

        /// Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.

        /// Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the public key in the first certificate in x5c with the algorithm specified in alg.
        validateSignature(registrationObject);

        /// Verify that the public key in the first certificate in x5c matches the credentialPublicKey in the attestedCredentialData in authenticatorData.
        PublicKey publicKeyInEndEntityCert = attestationStatement.getX5c().getEndEntityAttestationCertificate().getCertificate().getPublicKey();
        PublicKey publicKeyInCredentialData = registrationObject.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getCredentialPublicKey().getPublicKey();
        if (!publicKeyInEndEntityCert.equals(publicKeyInCredentialData)) {
            throw new PublicKeyMismatchException("The public key in the first certificate in x5c doesn't matches the credentialPublicKey in the attestedCredentialData in authenticatorData.");
        }

        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(registrationObject.getCollectedClientDataBytes());
        keyDescriptionValidator.validate(attestationStatement.getX5c().getEndEntityAttestationCertificate().getCertificate(), clientDataHash, teeEnforcedOnly);

        return AttestationType.BASIC;
    }


    @Override
    public boolean supports(RegistrationObject registrationObject) {
        AttestationStatement attestationStatement = registrationObject.getAttestationObject().getAttestationStatement();
        return AndroidKeyAttestationStatement.class.isAssignableFrom(attestationStatement.getClass());
    }

    private void validateSignature(RegistrationObject registrationObject) {
        AndroidKeyAttestationStatement attestationStatement = (AndroidKeyAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement();

        byte[] signedData = getSignedData(registrationObject);
        byte[] signature = attestationStatement.getSig();
        PublicKey publicKey = getPublicKey(attestationStatement);

        try {
            Signature verifier = SignatureUtil.createSignature(attestationStatement.getAlg().getJcaName());
            verifier.initVerify(publicKey);
            verifier.update(signedData);
            if (verifier.verify(signature)) {
                return;
            }
            throw new BadSignatureException("Bad signature");
        } catch (SignatureException | InvalidKeyException e) {
            throw new BadSignatureException("Bad signature", e);
        }
    }

    private byte[] getSignedData(RegistrationObject registrationObject) {
        MessageDigest messageDigest = MessageDigestUtil.createSHA256();
        byte[] authenticatorData = registrationObject.getAuthenticatorDataBytes();
        byte[] clientDataHash = messageDigest.digest(registrationObject.getCollectedClientDataBytes());
        return ByteBuffer.allocate(authenticatorData.length + clientDataHash.length).put(authenticatorData).put(clientDataHash).array();
    }

    private PublicKey getPublicKey(AndroidKeyAttestationStatement attestationStatement) {
        Certificate cert = attestationStatement.getX5c().getEndEntityAttestationCertificate().getCertificate();
        return cert.getPublicKey();
    }
}
