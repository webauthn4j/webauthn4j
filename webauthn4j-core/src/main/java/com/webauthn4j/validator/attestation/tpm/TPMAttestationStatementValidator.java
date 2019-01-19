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

package com.webauthn4j.validator.attestation.tpm;

import com.webauthn4j.response.attestation.statement.*;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.util.SignatureUtil;
import com.webauthn4j.util.WIP;
import com.webauthn4j.util.exception.NotImplementedException;
import com.webauthn4j.validator.RegistrationObject;
import com.webauthn4j.validator.attestation.AttestationStatementValidator;
import com.webauthn4j.validator.exception.BadAttestationStatementException;
import com.webauthn4j.validator.exception.UnsupportedAttestationFormatException;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;

@WIP
public class TPMAttestationStatementValidator implements AttestationStatementValidator {

    @Override
    public AttestationType validate(RegistrationObject registrationObject) {
        if (!supports(registrationObject)) {
            throw new UnsupportedAttestationFormatException("Specified format is not supported by " + this.getClass().getName());
        }
        TPMAttestationStatement attestationStatement = (TPMAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement();

        if (!attestationStatement.getVer().equals(TPMAttestationStatement.VERSION_2_0)){
            throw new BadAttestationStatementException("TPM version is not supported");
        }

        /// Verify that the public key specified by the parameters and unique fields of pubArea is identical to the credentialPublicKey in the attestedCredentialData in authenticatorData.

        PublicKey publicKeyInAuthData =
                registrationObject.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getCredentialPublicKey().getPublicKey();
        // TODO

        TPMSAttest certInfo = attestationStatement.getCertInfo();
        TPMTPublic pubArea = attestationStatement.getPubArea();
        /// Concatenate authenticatorData and clientDataHash to form attToBeSigned.

        /// Validate that certInfo is valid:

        /// Verify that magic is set to TPM_GENERATED_VALUE.
        if(certInfo.getMagic() != TPMGenerated.TPM_GENERATED_VALUE){
            throw new BadAttestationStatementException("magic must be TPM_GENERATED_VALUE");
        }

        /// Verify that type is set to TPM_ST_ATTEST_CERTIFY.
        if(certInfo.getType() == TPMISTAttest.TPM_ST_ATTEST_CERTIFY){
            throw new BadAttestationStatementException("type must be TPM_ST_ATTEST_CERTIFY");
        }

        /// Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg".
        byte[] signedData = getSignedData(registrationObject, attestationStatement.getAlg());
        if(Arrays.equals(certInfo.getExtraData(), signedData)){
            throw new BadAttestationStatementException("extraData must be equals to the hash of attToBeSigned");
        }

        /// Verify that attested contains a TPMS_CERTIFY_INFO structure as specified in [TPMv2-Part2] section 10.12.3,
        /// whose name field contains a valid Name for pubArea, as computed using the algorithm in the nameAlg field of
        /// pubArea using the procedure specified in [TPMv2-Part1] section 16.
        TPMSCertifyInfo certifyInfo = (TPMSCertifyInfo) certInfo.getAttested();
        certifyInfo.getName();
        //TODO

        /// Note that the remaining fields in the "Standard Attestation Structure" [TPMv2-Part1] section 31.2,
        /// i.e., qualifiedSigner, clockInfo and firmwareVersion are ignored. These fields MAY be used as an input to risk engines.

        /// If x5c is present, this indicates that the attestation type is not ECDAA. In this case:

        if(attestationStatement.getX5c() != null){
            /// Verify the sig is a valid signature over certInfo using the attestation public key in aikCert with the algorithm specified in alg.
            //TODO
            /// Verify that aikCert meets the requirements in §8.3.1 TPM Attestation Statement Certificate Requirements.
            //TODO
            /// If aikCert contains an extension with OID 1 3 6 1 4 1 45724 1 1 4 (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid in authenticatorData.
            //TODO
            /// If successful, return implementation-specific values representing attestation type AttCA and attestation trust path x5c.
            return AttestationType.ATT_CA;
        }
        //If ecdaaKeyId is present, then the attestation type is ECDAA.
        if(attestationStatement.getEcdaaKeyId() != null){
            /// Perform ECDAA-Verify on sig to verify that it is a valid signature over certInfo (see  [FIDOEcdaaAlgorithm]).
            /// If successful, return implementation-specific values representing attestation type ECDAA and attestation trust path ecdaaKeyId.
            throw new NotImplementedException();
        }
        throw new BadAttestationStatementException("x5c or ecdaaKeyId must be present");
    }

    @Override
    public boolean supports(RegistrationObject registrationObject) {
        AttestationStatement attestationStatement = registrationObject.getAttestationObject().getAttestationStatement();
        return TPMAttestationStatement.class.isAssignableFrom(attestationStatement.getClass());
    }

    private byte[] getSignedData(RegistrationObject registrationObject, COSEAlgorithmIdentifier alg) {
        MessageDigest messageDigest = MessageDigestUtil.createMessageDigest(alg.getMessageDigestJcaName());
        byte[] authenticatorData = registrationObject.getAuthenticatorDataBytes();
        byte[] clientDataHash = messageDigest.digest(registrationObject.getCollectedClientDataBytes());
        return ByteBuffer.allocate(authenticatorData.length + clientDataHash.length).put(authenticatorData).put(clientDataHash).array();
    }
}
