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

package com.webauthn4j.validator.attestation.statement.tpm;

import com.webauthn4j.response.attestation.authenticator.AAGUID;
import com.webauthn4j.response.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.response.attestation.statement.*;
import com.webauthn4j.util.ECUtil;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.util.UnsignedNumberUtil;
import com.webauthn4j.util.exception.NotImplementedException;
import com.webauthn4j.validator.RegistrationObject;
import com.webauthn4j.validator.attestation.statement.AbstractStatementValidator;
import com.webauthn4j.validator.exception.BadAttestationStatementException;
import com.webauthn4j.validator.exception.BadSignatureException;
import org.apache.kerby.asn1.type.Asn1Utf8String;

import javax.naming.NamingException;
import javax.naming.ldap.LdapName;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EllipticCurve;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class TPMAttestationStatementValidator extends AbstractStatementValidator<TPMAttestationStatement> {

    private static final String ID_FIDO_GEN_CE_AAGUID = "1.3.6.1.4.1.45724.1.1.4";

    // ~ Instance fields
    // ================================================================================================

    private TPMDevicePropertyValidator tpmDevicePropertyValidator = new NullTPMDevicePropertyValidator();

    @Override
    public AttestationType validate(RegistrationObject registrationObject) {
        if (!supports(registrationObject)) {
            throw new IllegalArgumentException("Specified format is not supported by " + this.getClass().getName());
        }
        TPMAttestationStatement attestationStatement = (TPMAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement();

        if (!attestationStatement.getVer().equals(TPMAttestationStatement.VERSION_2_0)){
            throw new BadAttestationStatementException("TPM version is not supported");
        }

        TPMSAttest certInfo = attestationStatement.getCertInfo();
        TPMTPublic pubArea = attestationStatement.getPubArea();
        AuthenticatorData authenticatorData = registrationObject.getAttestationObject().getAuthenticatorData();

        /// Verify that the public key specified by the parameters and unique fields of pubArea is identical to the credentialPublicKey in the attestedCredentialData in authenticatorData.
        validatePublicKeyEquality(pubArea, authenticatorData);

        /// Concatenate authenticatorData and clientDataHash to form attToBeSigned.
        byte[] attToBeSigned = getAttToBeSigned(registrationObject);

        /// Validate that certInfo is valid:

        /// Verify that magic is set to TPM_GENERATED_VALUE.
        if(certInfo.getMagic() != TPMGenerated.TPM_GENERATED_VALUE){
            throw new BadAttestationStatementException("magic must be TPM_GENERATED_VALUE");
        }

        /// Verify that type is set to TPM_ST_ATTEST_CERTIFY.
        if(certInfo.getType() != TPMISTAttest.TPM_ST_ATTEST_CERTIFY){
            throw new BadAttestationStatementException("type must be TPM_ST_ATTEST_CERTIFY");
        }

        /// Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg".
        byte[] hash = MessageDigestUtil.createMessageDigest(attestationStatement.getAlg().getMessageDigestJcaName()).digest(attToBeSigned);
        if(!Arrays.equals(certInfo.getExtraData(), hash)){
            throw new BadAttestationStatementException("extraData must be equals to the hash of attToBeSigned");
        }

        /// Verify that attested contains a TPMS_CERTIFY_INFO structure as specified in [TPMv2-Part2] section 10.12.3,
        /// whose name field contains a valid Name for pubArea, as computed using the algorithm in the nameAlg field of
        /// pubArea using the procedure specified in [TPMv2-Part1] section 16.
        TPMSCertifyInfo certifyInfo = (TPMSCertifyInfo) certInfo.getAttested();
        TPMIAlgHash alg = certifyInfo.getName().getHashAlg();
        String algJcaName;
        algJcaName = getAlgJcaName(alg);

        byte[] pubAreaDigest = MessageDigestUtil.createMessageDigest(algJcaName).digest(pubArea.getBytes());
        if(!Arrays.equals(pubAreaDigest, certifyInfo.getName().getDigest())){
            throw new BadAttestationStatementException("hash of attested doesn't match with name field of certifyInfo");
        }

        /// Note that the remaining fields in the "Standard Attestation Structure" [TPMv2-Part1] section 31.2,
        /// i.e., qualifiedSigner, clockInfo and firmwareVersion are ignored. These fields MAY be used as an input to risk engines.

        /// If x5c is present, this indicates that the attestation type is not ECDAA. In this case:
        if(attestationStatement.getX5c() != null){
            validateX5c(attestationStatement, certInfo, authenticatorData);
            /// If successful, return implementation-specific values representing attestation type AttCA and attestation trust path x5c.
            return AttestationType.ATT_CA;
        }
        //If ecdaaKeyId is present, then the attestation type is ECDAA.
        if(attestationStatement.getEcdaaKeyId() != null){
            /// Perform ECDAA-Verify on sig to verify that it is a valid signature over certInfo (see  [FIDOEcdaaAlgorithm]).
            /// If successful, return implementation-specific values representing attestation type ECDAA and attestation trust path ecdaaKeyId.
            throw new NotImplementedException();
            // When it is implemented, `AttestationType.ECDAA` is to be returned.
        }
        throw new BadAttestationStatementException("x5c or ecdaaKeyId must be present");
    }

    private void validateX5c(TPMAttestationStatement attestationStatement, TPMSAttest certInfo, AuthenticatorData authenticatorData) {
        X509Certificate aikCert = attestationStatement.getX5c().getEndEntityAttestationCertificate().getCertificate();

        /// Verify the sig is a valid signature over certInfo using the attestation public key in aikCert with the algorithm specified in alg.

        try {
            attestationStatement.getAlg().signatureVerifier()
                    .publicKey(aikCert.getPublicKey())
                    .update(certInfo.getBytes())
                    .verify(attestationStatement.getSig());
        } catch (BadSignatureException e) {
            throw new BadAttestationStatementException("hash of certInfo doesn't match with sig", e);
        }

        /// Verify that aikCert meets the requirements in §8.3.1 TPM Attestation Statement Certificate Requirements.
        validateAikCert(aikCert);

        /// If aikCert contains an extension with OID 1 3 6 1 4 1 45724 1 1 4 (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid in authenticatorData.
        byte[] aaguidBytes = aikCert.getExtensionValue(ID_FIDO_GEN_CE_AAGUID);
        if(aaguidBytes !=null && !Objects.equals(new AAGUID(aaguidBytes), authenticatorData.getAttestedCredentialData().getAaguid())){
            throw new BadAttestationStatementException("AAGUID in aikCert doesn't match with that in authenticatorData");
        }
    }

    String getAlgJcaName(TPMIAlgHash alg) {
        String algJcaName;
        switch (alg){
            case TPM_ALG_SHA1:
                algJcaName = "SHA-1";
                break;
            case TPM_ALG_SHA256:
                algJcaName = "SHA-256";
                break;
            case TPM_ALG_SHA384:
                algJcaName = "SHA-384";
                break;
            case TPM_ALG_SHA512:
                algJcaName = "SHA-512";
                break;
            default:
                throw new BadAttestationStatementException("nameAlg '" + alg.name() + "' is not supported.");
        }
        return algJcaName;
    }

    public TPMDevicePropertyValidator getTpmDevicePropertyValidator() {
        return tpmDevicePropertyValidator;
    }

    public void setTpmDevicePropertyValidator(TPMDevicePropertyValidator tpmDevicePropertyValidator) {
        this.tpmDevicePropertyValidator = tpmDevicePropertyValidator;
    }

    private void validatePublicKeyEquality(TPMTPublic pubArea, AuthenticatorData authenticatorData) {
        PublicKey publicKeyInAuthData =
                authenticatorData.getAttestedCredentialData().getCredentialPublicKey().getPublicKey();
        TPMUPublicId publicKeyInPubArea = pubArea.getUnique();

        if(pubArea.getType() == TPMIAlgPublic.TPM_ALG_RSA && publicKeyInPubArea instanceof RSAUnique){
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKeyInAuthData;
            TPMSRSAParms parms = (TPMSRSAParms)pubArea.getParameters();
            RSAUnique rsaUnique = (RSAUnique) publicKeyInPubArea;
            long exponent = UnsignedNumberUtil.getUnsignedInt(parms.getExponent());
            if(exponent == 0){
                exponent = 65537; // 2^16 + 1
            }
            if (rsaPublicKey.getModulus().equals(new BigInteger(1, rsaUnique.getN())) &&
                rsaPublicKey.getPublicExponent().equals(BigInteger.valueOf(exponent))) {
                return;
            }
        }
        else if(pubArea.getType() == TPMIAlgPublic.TPM_ALG_ECDSA && publicKeyInPubArea instanceof ECCUnique){
            ECPublicKey ecPublicKey = (ECPublicKey) publicKeyInAuthData;
            TPMSECCParms parms = (TPMSECCParms)pubArea.getParameters();
            EllipticCurve curveInParms = getCurveFromTPMEccCurve(parms.getCurveId());
            ECCUnique eccUnique = (ECCUnique) publicKeyInPubArea;
            if (ecPublicKey.getParams().getCurve().equals(curveInParms) &&
                ecPublicKey.getW().getAffineX().equals(new BigInteger(1, eccUnique.getX())) &&
                ecPublicKey.getW().getAffineY().equals(new BigInteger(1, eccUnique.getY()))) {
                return;
            }
        }
        throw new BadAttestationStatementException("publicKey in authData and publicKey in unique pubArea doesn't match");
    }

    EllipticCurve getCurveFromTPMEccCurve(TPMEccCurve curveId) {
        switch (curveId){
            case TPM_ECC_NIST_P256:
                return ECUtil.P_256_SPEC.getCurve();
            case TPM_ECC_NIST_P384:
                return ECUtil.P_384_SPEC.getCurve();
            case TPM_ECC_NIST_P521:
                return ECUtil.P_521_SPEC.getCurve();
            default:
                throw new NotImplementedException();
        }
    }

    private void validateAikCert(X509Certificate certificate){
        try {
            /// TPM attestation certificate MUST have the following fields/extensions:
            /// Version MUST be set to 3.
            if(!Objects.equals(certificate.getVersion(), 3)){
                throw new BadAttestationStatementException("x5c must be version 3.");
            }
            /// Subject field MUST be set to empty.
            if(!certificate.getSubjectDN().getName().isEmpty()){
                throw new BadAttestationStatementException("x5c subject field MUST be set to empty");
            }
            /// The Subject Alternative Name extension MUST be set as defined in [TPMv2-EK-Profile] section 3.2.9.
            validateSubjectAlternativeName(certificate);
            /// The Extended Key Usage extension MUST contain the "joint-iso-itu-t(2) internationalorganizations(23) 133 tcg-kp(8) tcg-kp-AIKCertificate(3)" OID.
            if(!certificate.getExtendedKeyUsage().contains("2.23.133.8.3")){
                throw new BadAttestationStatementException("Attestation certificate doesn't contain tcg-kp-AIKCertificate (2.23.133.8.3) OID");
            }
            /// The Basic Constraints extension MUST have the CA component set to false.
            if(certificate.getBasicConstraints() != -1){
                throw new BadAttestationStatementException("The Basic Constraints extension of attestation certificate must have the CA component set to false");
            }
            /// An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL Distribution Point
            /// extension [RFC5280] are both OPTIONAL as the status of many attestation certificates is available
            /// through metadata services. See, for example, the FIDO Metadata Service  [FIDOMetadataService].

        } catch (CertificateParsingException e) {
            throw new BadAttestationStatementException("Failed to parse attestation certificate", e);
        }
    }

    private void validateSubjectAlternativeName(X509Certificate certificate) throws CertificateParsingException {

        try{
            for(List entry : certificate.getSubjectAlternativeNames()){
                if(entry.get(0).equals(4)){
                    LdapName directoryName = new LdapName((String) entry.get(1));
                    directoryName.getRdns();
                    byte[] manufacturerAttr = (byte[])directoryName.getRdns().get(0).toAttributes().get("2.23.133.2.1").get();
                    byte[] partNumberAttr = (byte[])directoryName.getRdns().get(0).toAttributes().get("2.23.133.2.2").get();
                    byte[] firmwareVersionAttr = (byte[])directoryName.getRdns().get(0).toAttributes().get("2.23.133.2.3").get();

                    if(manufacturerAttr != null && partNumberAttr != null && firmwareVersionAttr != null){
                        Asn1Utf8String manufacturerUtf8String = new Asn1Utf8String();
                        manufacturerUtf8String.decode(manufacturerAttr);
                        Asn1Utf8String partNumberUtf8String = new Asn1Utf8String();
                        partNumberUtf8String.decode(partNumberAttr);
                        Asn1Utf8String firmwareVersionUtf8String = new Asn1Utf8String();
                        firmwareVersionUtf8String.decode(firmwareVersionAttr);

                        String manufacturer = manufacturerUtf8String.getValue();
                        String partNumber = partNumberUtf8String.getValue();
                        String firmwareVersion = firmwareVersionUtf8String.getValue();
                        tpmDevicePropertyValidator.validate(new TPMDeviceProperty(manufacturer, partNumber, firmwareVersion));
                        return;
                    }
                }
            }
        } catch (NamingException | IOException | RuntimeException e) {
            throw new BadAttestationStatementException("The Subject Alternative Name extension of attestation certificate dosn't contain TPM device property", e);
        }
        throw new BadAttestationStatementException("The Subject Alternative Name extension of attestation certificate dosn't contain TPM device property");
    }

    private byte[] getAttToBeSigned(RegistrationObject registrationObject) {
        MessageDigest messageDigest = MessageDigestUtil.createSHA256();
        byte[] authenticatorData = registrationObject.getAuthenticatorDataBytes();
        byte[] clientDataHash = messageDigest.digest(registrationObject.getCollectedClientDataBytes());
        return ByteBuffer.allocate(authenticatorData.length + clientDataHash.length).put(authenticatorData).put(clientDataHash).array();
    }
}
