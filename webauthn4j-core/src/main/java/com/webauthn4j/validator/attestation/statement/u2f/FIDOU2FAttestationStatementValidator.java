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

package com.webauthn4j.validator.attestation.statement.u2f;

import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.EC2CredentialPublicKey;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.AttestationType;
import com.webauthn4j.data.attestation.statement.FIDOU2FAttestationStatement;
import com.webauthn4j.util.ECUtil;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.validator.RegistrationObject;
import com.webauthn4j.validator.attestation.statement.AbstractStatementValidator;
import com.webauthn4j.validator.exception.BadAttestationStatementException;
import com.webauthn4j.validator.exception.BadSignatureException;
import com.webauthn4j.validator.exception.CertificateException;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.ECPublicKey;

/**
 * Validates the specified {@link AttestationStatement} is a valid FIDO-U2F attestation
 */
public class FIDOU2FAttestationStatementValidator extends AbstractStatementValidator<FIDOU2FAttestationStatement> {

    /**
     * {@link AttestationType}.BASIC is always returned as RP cannot differentiate between BASIC and Attestation CA from the attestation data,
     *
     * @return AttestationType.BASIC
     */
    @Override
    public AttestationType validate(RegistrationObject registrationObject) {
        if (!supports(registrationObject)) {
            throw new IllegalArgumentException("Specified format is not supported by " + this.getClass().getName());
        }

        FIDOU2FAttestationStatement attestationStatement =
                (FIDOU2FAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement();
        validateAttestationStatement(attestationStatement);
        validateSignature(registrationObject);
        return AttestationType.BASIC;
    }

    void validateAttestationStatement(FIDOU2FAttestationStatement attestationStatement) {
        if (attestationStatement.getX5c().size() != 1) {
            throw new BadAttestationStatementException("FIDO-U2F attestation statement must have only one certificate.");
        }
        PublicKey publicKey = attestationStatement.getX5c().getEndEntityAttestationCertificate().getCertificate().getPublicKey();
        validatePublicKey(publicKey);
    }

    void validatePublicKey(PublicKey publicKey) {
        if (!publicKey.getAlgorithm().equals("EC")) {
            throw new CertificateException("FIDO-U2F attestation statement supports ECDSA only.");
        }
        if (!((ECPublicKey) publicKey).getParams().equals(ECUtil.P_256_SPEC)) {
            throw new CertificateException("FIDO-U2F attestation statement supports secp256r1 curve only.");
        }
    }

    private void validateSignature(RegistrationObject registrationObject) {
        FIDOU2FAttestationStatement attestationStatement = (FIDOU2FAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement();

        byte[] signedData = getSignedData(registrationObject);
        byte[] signature = attestationStatement.getSig();
        PublicKey publicKey = getPublicKey(attestationStatement);

        try {
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(publicKey);
            verifier.update(signedData);
            if (verifier.verify(signature)) {
                return;
            }
            throw new BadSignatureException("`sig` in attestation statement is not valid signature over the concatenation of authenticatorData and clientDataHash.");
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            throw new BadSignatureException("`sig` in attestation statement is not valid signature over the concatenation of authenticatorData and clientDataHash.");
        }
    }

    private byte[] getSignedData(RegistrationObject registrationObject) {

        String rpId = registrationObject.getServerProperty().getRpId();
        MessageDigest messageDigest = MessageDigestUtil.createSHA256();

        AttestationObject attestationObject = registrationObject.getAttestationObject();
        EC2CredentialPublicKey credentialPublicKey =
                (EC2CredentialPublicKey) attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialPublicKey();

        byte[] rpIdBytes = rpId.getBytes(StandardCharsets.UTF_8);

        byte[] clientDataJsonBytes = registrationObject.getCollectedClientDataBytes();

        byte[] applicationParameter = messageDigest.digest(rpIdBytes);
        byte[] challengeParameter = messageDigest.digest(clientDataJsonBytes);
        byte[] keyHandle = attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId();
        byte[] userPublicKeyBytes = credentialPublicKey.getBytes();

        ByteBuffer byteBuffer = ByteBuffer.allocate(1 + 32 + 32 + keyHandle.length + 65);
        byteBuffer.put((byte) 0x00); //RFU
        byteBuffer.put(applicationParameter);
        byteBuffer.put(challengeParameter);
        byteBuffer.put(keyHandle);
        byteBuffer.put(userPublicKeyBytes);
        return byteBuffer.array();
    }

    private PublicKey getPublicKey(FIDOU2FAttestationStatement attestationStatement) {
        Certificate cert = attestationStatement.getX5c().getEndEntityAttestationCertificate().getCertificate();
        return cert.getPublicKey();
    }

}
