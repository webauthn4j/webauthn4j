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

package com.webauthn4j.verifier.attestation.statement.u2f;

import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.AttestationType;
import com.webauthn4j.data.attestation.statement.FIDOU2FAttestationStatement;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.ECUtil;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.util.SignatureUtil;
import com.webauthn4j.verifier.CoreRegistrationObject;
import com.webauthn4j.verifier.attestation.statement.AbstractStatementVerifier;
import com.webauthn4j.verifier.exception.BadAttestationStatementException;
import com.webauthn4j.verifier.exception.BadSignatureException;
import com.webauthn4j.verifier.exception.CertificateException;
import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;

/**
 * Verifies the specified {@link AttestationStatement} is a valid FIDO U2F attestation
 * according to WebAuthn Level 3 specification.
 * <p>
 * Implements the verification procedure defined in:
 * <a href="https://www.w3.org/TR/webauthn-3/#sctn-fido-u2f-attestation">
 * WebAuthn Level 3 § 8.6 FIDO U2F Attestation Statement Format</a>
 * <p>
 * Also references FIDO U2F Raw Message Formats specification for signature verification.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/">Web Authentication: An API for accessing Public Key Credentials - Level 3</a>
 */
public class FIDOU2FAttestationStatementVerifier extends AbstractStatementVerifier<FIDOU2FAttestationStatement> {

    /**
     * Verifies a FIDO U2F attestation statement.
     * <p>
     * Note: {@link AttestationType}.BASIC is always returned as RP cannot differentiate
     * between BASIC and Attestation CA from the attestation data.
     *
     * @param registrationObject the registration object containing attestation data
     * @return AttestationType.BASIC
     */
    @Override
    public @NotNull AttestationType verify(@NotNull CoreRegistrationObject registrationObject) {
        AssertUtil.notNull(registrationObject, "registrationObject must not be null");
        if (!supports(registrationObject)) {
            throw new IllegalArgumentException("Specified format is not supported by " + this.getClass().getName());
        }

        FIDOU2FAttestationStatement attestationStatement =
                (FIDOU2FAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement();
        verifyAttestationStatementNotNull(attestationStatement);
        //spec| Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
        //spec| Check that x5c has exactly one element and let attCert be that element. Let certificate public key be the public key conveyed by attCert. If certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve, terminate this algorithm and return an appropriate error.
        verifyAttestationStatement(attestationStatement);
        //spec| Extract the claimed rpIdHash from authenticatorData, and the claimed credentialId and credentialPublicKey from authenticatorData.attestedCredentialData.
        //spec| Convert the COSE_KEY formatted credentialPublicKey (see Section 7 of [RFC9052]) to Raw ANSI X9.62 public key format (see ALG_KEY_ECC_X962_RAW in Section 3.6.2 Public Key Representation Formats of [FIDO-Registry]).
        //spec| Let verificationData be the concatenation of (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F) (see Section 4.3 of [FIDO-U2F-Message-Formats]).
        //spec| Verify the sig using verificationData and the certificate public key per section 4.1.4 of [SEC1] with SHA-256 as the hash function used in step two.
        verifySignature(registrationObject);
        //spec| Optionally, inspect x5c and consult externally provided knowledge to determine whether attStmt conveys a Basic or AttCA attestation.
        //spec| If successful, return implementation-specific values representing attestation type Basic, AttCA or uncertainty, and attestation trust path x5c.
        return AttestationType.BASIC;
    }

    void verifyAttestationStatementNotNull(FIDOU2FAttestationStatement attestationStatement) {
        if (attestationStatement == null) {
            throw new BadAttestationStatementException("attestation statement is not found.");
        }
    }

    void verifyAttestationStatement(@NotNull FIDOU2FAttestationStatement attestationStatement) {
        if (attestationStatement.getX5c().size() != 1) {
            throw new BadAttestationStatementException("FIDO-U2F attestation statement must have only one certificate.", attestationStatement);
        }
        X509Certificate certificate = attestationStatement.getX5c().getEndEntityAttestationCertificate().getCertificate();
        verifyPublicKey(certificate);
    }

    void verifyPublicKey(@NotNull X509Certificate certificate) {
        PublicKey publicKey = certificate.getPublicKey();
        if (!publicKey.getAlgorithm().equals("EC")) {
            throw new CertificateException("FIDO-U2F attestation statement supports ECDSA only.", certificate);
        }
        if (!((ECPublicKey) publicKey).getParams().equals(ECUtil.P_256_SPEC)) {
            throw new CertificateException("FIDO-U2F attestation statement supports secp256r1 curve only.", certificate);
        }
    }

    private void verifySignature(@NotNull CoreRegistrationObject registrationObject) {
        FIDOU2FAttestationStatement attestationStatement = (FIDOU2FAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement();

        byte[] signedData = getSignedData(registrationObject);
        byte[] signature = attestationStatement.getSig();
        PublicKey publicKey = getPublicKey(attestationStatement);

        try {
            Signature verifier = SignatureUtil.createES256();
            verifier.initVerify(publicKey);
            verifier.update(signedData);
            if (verifier.verify(signature)) {
                return;
            }
            throw new BadSignatureException("`sig` in attestation statement is not valid signature. Please refer U2F Raw Message Formats. https://fidoalliance.org/specs/fido-u2f-v1.1-id-20160915/fido-u2f-raw-message-formats-v1.1-id-20160915.html");
        } catch (SignatureException | InvalidKeyException e) {
            throw new BadSignatureException("`sig` in attestation statement is not valid signature. Please refer U2F Raw Message Formats. https://fidoalliance.org/specs/fido-u2f-v1.1-id-20160915/fido-u2f-raw-message-formats-v1.1-id-20160915.html");
        }
    }

    private byte[] getSignedData(@NotNull CoreRegistrationObject registrationObject) {

        String rpId = registrationObject.getServerProperty().getRpId();
        MessageDigest messageDigest = MessageDigestUtil.createSHA256();

        AttestationObject attestationObject = registrationObject.getAttestationObject();
        //noinspection ConstantConditions as null check is already done in caller
        EC2COSEKey credentialPublicKey =
                (EC2COSEKey) attestationObject.getAuthenticatorData().getAttestedCredentialData().getCOSEKey();

        byte[] rpIdBytes = rpId.getBytes(StandardCharsets.UTF_8);

        byte[] applicationParameter = messageDigest.digest(rpIdBytes);
        byte[] challengeParameter = registrationObject.getClientDataHash();
        byte[] keyHandle = attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId();
        byte[] userPublicKeyBytes = getPublicKeyBytes(credentialPublicKey);

        ByteBuffer byteBuffer = ByteBuffer.allocate(1 + 32 + 32 + keyHandle.length + 65);
        byteBuffer.put((byte) 0x00); //RFU
        byteBuffer.put(applicationParameter);
        byteBuffer.put(challengeParameter);
        byteBuffer.put(keyHandle);
        byteBuffer.put(userPublicKeyBytes);
        return byteBuffer.array();
    }

    private byte[] getPublicKeyBytes(@NotNull EC2COSEKey ec2CoseKey) {
        byte[] x = ec2CoseKey.getX();
        byte[] y = ec2CoseKey.getY();
        byte format = 0x04;
        return ByteBuffer.allocate(1 + x.length + y.length).put(format).put(x).put(y).array();
    }

    private PublicKey getPublicKey(@NotNull FIDOU2FAttestationStatement attestationStatement) {
        Certificate cert = attestationStatement.getX5c().getEndEntityAttestationCertificate().getCertificate();
        return cert.getPublicKey();
    }

}
