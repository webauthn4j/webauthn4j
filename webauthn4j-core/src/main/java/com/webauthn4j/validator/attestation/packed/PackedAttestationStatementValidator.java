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

package com.webauthn4j.validator.attestation.packed;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.attestation.authenticator.CredentialPublicKey;
import com.webauthn4j.attestation.statement.AttestationStatement;
import com.webauthn4j.attestation.statement.AttestationType;
import com.webauthn4j.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.converter.jackson.ObjectMapperUtil;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.util.exception.NotImplementedException;
import com.webauthn4j.validator.RegistrationObject;
import com.webauthn4j.validator.attestation.AttestationStatementValidator;
import com.webauthn4j.validator.exception.BadAlgorithmException;
import com.webauthn4j.validator.exception.BadAttestationStatementException;
import com.webauthn4j.validator.exception.BadSignatureException;
import com.webauthn4j.validator.exception.UnsupportedAttestationFormatException;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Arrays;

public class PackedAttestationStatementValidator implements AttestationStatementValidator {

    private final ObjectMapper objectMapper = ObjectMapperUtil.createCBORMapper();

    @Override
    public AttestationType validate(RegistrationObject registrationObject) {
        if (!supports(registrationObject)) {
            throw new UnsupportedAttestationFormatException("Specified format is not supported by " + this.getClass().getName());
        }

        PackedAttestationStatement attestationStatement = (PackedAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement();
        byte[] sig = attestationStatement.getSig();
        COSEAlgorithmIdentifier alg = attestationStatement.getAlg();
        byte[] signedData = getSignedData(registrationObject);
        // If x5c is present, this indicates that the attestation type is not ECDAA. In this case:
        if (attestationStatement.getX5c() != null) {
            // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash
            // using the attestation public key in x5c with the algorithm specified in alg.
            if (verifySignature(attestationStatement.getX5c().getEndEntityAttestationCertificate().getCertificate().getPublicKey(), alg, sig, signedData)) {
                throw new BadSignatureException("Bad signature");
            }
            // Verify that x5c meets the requirements in §8.2.1 Packed attestation statement certificate requirements.
            attestationStatement.getX5c().getEndEntityAttestationCertificate().validate();

            // If x5c contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that
            // the value of this extension matches the aaguid in authenticatorData.
            byte[] aaguidInCertificate = attestationStatement.getX5c().getEndEntityAttestationCertificate().getCertificate().getExtensionValue("1.3.6.1.4.1.45724.1.1.4");
            byte[] aaguid = registrationObject.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getAaGuid();
            if (aaguidInCertificate != null && !Arrays.equals(aaguidInCertificate, aaguid)) {
                throw new BadAttestationStatementException("Bad aaguid");
            }

            // If successful, return attestation type BASIC and attestation trust path x5c.
            return AttestationType.BASIC;
        }
        // If ecdaaKeyId is present, then the attestation type is ECDAA. In this case:
        else if (attestationStatement.getEcdaaKeyId() != null) {
            // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash
            // using ECDAA-Verify with ECDAA-Issuer public key identified by ecdaaKeyId (see [FIDOEcdaaAlgorithm]).
            // TODO
            throw new NotImplementedException();
            // If successful, return attestation type ECDAA and attestation trust path ecdaaKeyId.
            // return AttestationType.ECDAA;
        }
        // If neither x5c nor ecdaaKeyId is present, self attestation is in use.
        else {
            CredentialPublicKey credentialPublicKey =
                    registrationObject.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getCredentialPublicKey();
            // Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData.
            COSEAlgorithmIdentifier credentialPublicKeyAlgorithm = credentialPublicKey.getAlgorithm();
            if (!alg.equals(credentialPublicKeyAlgorithm)) {
                throw new BadAlgorithmException("Algorithm doesn't match");
            }
            // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the credential public key with alg.
            if (verifySignature(credentialPublicKey.getPublicKey(), alg, sig, signedData)) {
                throw new BadSignatureException("Bad signature");
            }
            // If successful, return attestation type Self and empty attestation trust path.
            return AttestationType.SELF;
        }
    }

    @Override
    public boolean supports(RegistrationObject registrationObject) {
        AttestationStatement attestationStatement = registrationObject.getAttestationObject().getAttestationStatement();
        return PackedAttestationStatement.class.isAssignableFrom(attestationStatement.getClass());
    }


    private boolean verifySignature(PublicKey publicKey, COSEAlgorithmIdentifier algorithmIdentifier, byte[] signature, byte[] data) {
        try {
            Signature verifier = Signature.getInstance(algorithmIdentifier.getName());
            verifier.initVerify(publicKey);
            verifier.update(data);

            return verifier.verify(signature);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | RuntimeException e) {
            return false;
        }
    }

    private byte[] getSignedData(RegistrationObject registrationObject) {
        MessageDigest messageDigest = MessageDigestUtil.createSHA256();
        byte[] authenticatorData = deriveAuthenticatorDataFromAttestationObject(registrationObject.getAttestationObjectBytes());
        byte[] clientDataHash = messageDigest.digest(registrationObject.getCollectedClientDataBytes());
        return ByteBuffer.allocate(authenticatorData.length + clientDataHash.length).put(authenticatorData).put(clientDataHash).array();
    }

    private byte[] deriveAuthenticatorDataFromAttestationObject(byte[] attestationObject) {
        try {
            return objectMapper.readTree(attestationObject).get("authData").binaryValue();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

}
