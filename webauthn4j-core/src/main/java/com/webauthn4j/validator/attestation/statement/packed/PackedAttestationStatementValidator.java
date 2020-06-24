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

package com.webauthn4j.validator.attestation.statement.packed;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.AttestationType;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.util.SignatureUtil;
import com.webauthn4j.util.UUIDUtil;
import com.webauthn4j.validator.RegistrationObject;
import com.webauthn4j.validator.attestation.statement.AbstractStatementValidator;
import com.webauthn4j.validator.exception.BadAlgorithmException;
import com.webauthn4j.validator.exception.BadAttestationStatementException;
import com.webauthn4j.validator.exception.BadSignatureException;
import org.apache.kerby.asn1.type.Asn1OctetString;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * Validates the specified {@link AttestationStatement} is a valid packed attestation
 */
public class PackedAttestationStatementValidator extends AbstractStatementValidator<PackedAttestationStatement> {

    private static final String ID_FIDO_GEN_CE_AAGUID = "1.3.6.1.4.1.45724.1.1.4";

    @Override
    public AttestationType validate(RegistrationObject registrationObject) {
        if (!supports(registrationObject)) {
            throw new IllegalArgumentException("Specified format is not supported by " + this.getClass().getName());
        }

        PackedAttestationStatement attestationStatement = (PackedAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement();
        byte[] sig = attestationStatement.getSig();
        COSEAlgorithmIdentifier alg = attestationStatement.getAlg();
        byte[] attrToBeSigned = getAttToBeSigned(registrationObject);
        // If x5c is present,
        if (attestationStatement.getX5c() != null) {
            return validateX5c(registrationObject, attestationStatement, sig, alg, attrToBeSigned);
        }
        // If x5c is not present, self attestation is in use.
        else {
            return validateSelfAttestation(registrationObject, sig, alg, attrToBeSigned);
        }
    }

    private AttestationType validateX5c(RegistrationObject registrationObject, PackedAttestationStatement attestationStatement, byte[] sig, COSEAlgorithmIdentifier alg, byte[] attrToBeSigned) {
        if (attestationStatement.getX5c() == null || attestationStatement.getX5c().isEmpty()) {
            throw new BadAttestationStatementException("No attestation certificate is found in packed attestation statement.");
        }

        // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash
        // using the attestation public key in x5c with the algorithm specified in alg.
        if (!verifySignature(attestationStatement.getX5c().getEndEntityAttestationCertificate().getCertificate().getPublicKey(), alg, sig, attrToBeSigned)) {
            throw new BadSignatureException("`sig` in attestation statement is not valid signature over the concatenation of authenticatorData and clientDataHash.");
        }
        // Verify that x5c meets the requirements in §8.2.1 Packed attestation statement certificate requirements.
        attestationStatement.getX5c().getEndEntityAttestationCertificate().validate();

        // If x5c contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that
        // the value of this extension matches the aaguid in authenticatorData.
        X509Certificate attestationCertificate = attestationStatement.getX5c().getEndEntityAttestationCertificate().getCertificate();
        AAGUID aaguidInCertificate = extractAAGUIDFromAttestationCertificate(attestationCertificate);
        AAGUID aaguid = registrationObject.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getAaguid();
        if (aaguidInCertificate != AAGUID.NULL && !Objects.equals(aaguidInCertificate, aaguid)) {
            throw new BadAttestationStatementException("AAGUID in attestation certificate doesn't match the AAGUID in authenticatorData.");
        }

        // If successful, return attestation type BASIC and attestation trust path x5c.
        return AttestationType.BASIC;
    }

    AAGUID extractAAGUIDFromAttestationCertificate(X509Certificate certificate) {
        byte[] extensionValue = certificate.getExtensionValue(ID_FIDO_GEN_CE_AAGUID);
        if (extensionValue == null) {
            return AAGUID.NULL;
        }
        try {
            Asn1OctetString envelope = new Asn1OctetString();
            envelope.decode(extensionValue);
            Asn1OctetString innerEnvelope = new Asn1OctetString();
            innerEnvelope.decode(envelope.getValue());
            return new AAGUID(UUIDUtil.fromBytes(innerEnvelope.getValue()));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private AttestationType validateSelfAttestation(RegistrationObject registrationObject, byte[] sig, COSEAlgorithmIdentifier alg, byte[] attrToBeSigned) {
        COSEKey coseKey =
                registrationObject.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getCOSEKey();
        // Validate that alg matches the algorithm of the coseKey in authenticatorData.
        COSEAlgorithmIdentifier credentialPublicKeyAlgorithm = coseKey.getAlgorithm();
        if (!alg.equals(credentialPublicKeyAlgorithm)) {
            throw new BadAlgorithmException("`alg` in attestation statement doesn't match the algorithm of the coseKey in authenticatorData.");
        }
        // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the credential public key with alg.
        if (!verifySignature(coseKey.getPublicKey(), alg, sig, attrToBeSigned)) {
            throw new BadSignatureException("`sig` in attestation statement is not valid signature over the concatenation of authenticatorData and clientDataHash.");
        }
        // If successful, return attestation type Self and empty attestation trust path.
        return AttestationType.SELF;
    }

    private boolean verifySignature(PublicKey publicKey, COSEAlgorithmIdentifier algorithmIdentifier, byte[] signature, byte[] data) {
        try {
            String jcaName = getJcaName(algorithmIdentifier);
            Signature verifier = SignatureUtil.createSignature(jcaName);
            verifier.initVerify(publicKey);
            verifier.update(data);

            return verifier.verify(signature);
        } catch (SignatureException | InvalidKeyException | RuntimeException e) {
            return false;
        }
    }

    private byte[] getAttToBeSigned(RegistrationObject registrationObject) {
        MessageDigest messageDigest = MessageDigestUtil.createSHA256();
        byte[] authenticatorData = registrationObject.getAuthenticatorDataBytes();
        byte[] clientDataHash = messageDigest.digest(registrationObject.getCollectedClientDataBytes());
        return ByteBuffer.allocate(authenticatorData.length + clientDataHash.length).put(authenticatorData).put(clientDataHash).array();
    }

}
