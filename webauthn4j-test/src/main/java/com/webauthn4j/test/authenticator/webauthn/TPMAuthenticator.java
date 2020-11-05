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

package com.webauthn4j.test.authenticator.webauthn;

import com.webauthn4j.data.SignatureAlgorithm;
import com.webauthn4j.data.attestation.statement.*;
import com.webauthn4j.test.AttestationCertificateBuilder;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.test.authenticator.webauthn.exception.WebAuthnModelException;
import com.webauthn4j.test.client.RegistrationEmulationOption;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.MessageDigestUtil;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyPurposeId;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

public class TPMAuthenticator extends WebAuthnModelAuthenticator {

    @Override
    public AttestationStatement createAttestationStatement(AttestationStatementRequest attestationStatementRequest, RegistrationEmulationOption registrationEmulationOption) {

        COSEAlgorithmIdentifier alg = COSEAlgorithmIdentifier.ES256;

        TPMTPublic pubArea = createTPMTPublic(attestationStatementRequest.getCredentialKeyPair().getPublic());
        TPMSAttest certInfo = createTPMSAttest(attestationStatementRequest, alg, pubArea);

        byte[] signature;
        if (registrationEmulationOption.isSignatureOverrideEnabled()) {
            signature = registrationEmulationOption.getSignature();
        }
        else {
            signature = TestDataUtil.calculateSignature(this.getAttestationKeyPair().getPrivate(), certInfo.getBytes());
        }

        AttestationOption attestationOption = registrationEmulationOption.getAttestationOption() == null ? new TPMAttestationOption() : registrationEmulationOption.getAttestationOption();
        AttestationCertificatePath attestationCertificatePath =
                new AttestationCertificatePath(getAttestationCertificate(attestationStatementRequest, attestationOption), this.getCACertificatePath());

        return new TPMAttestationStatement(alg, attestationCertificatePath, signature, certInfo, pubArea);
    }

    @Override
    public X509Certificate createAttestationCertificate(AttestationStatementRequest attestationStatementRequest, AttestationOption attestationOption) {
        AttestationCertificateBuilder builder =
                new AttestationCertificateBuilder(
                        getAttestationIssuerCertificate(),
                        new X500Principal(attestationOption.getSubjectDN()),
                        this.getAttestationKeyPair().getPublic());

        builder.addSubjectAlternativeNamesExtension("2.23.133.2.3=#0c0b69643a3030303230303030,2.23.133.2.2=#0c03535054,2.23.133.2.1=#0c0b69643a3439344535343433");

        if (attestationOption.isCAFlagInBasicConstraints()) {
            builder.addBasicConstraintsExtension();
        }
        if (attestationOption instanceof TPMAttestationOption) {
            TPMAttestationOption tpmAttestationOption = (TPMAttestationOption) attestationOption;
            if (tpmAttestationOption.isTcgKpAIKCertificateFlagInExtendedKeyUsage()) {
                builder.addExtendedKeyUsageExtension(KeyPurposeId.getInstance(new ASN1ObjectIdentifier("2.23.133.8.3")));
            }
        }
        return builder.build(this.getAttestationIssuerPrivateKey());
    }

    public X509Certificate createAttestationCertificate(AttestationStatementRequest attestationStatementRequest) {
        return createAttestationCertificate(attestationStatementRequest, new TPMAttestationOption());
    }


    private TPMSAttest createTPMSAttest(AttestationStatementRequest attestationStatementRequest, COSEAlgorithmIdentifier alg, TPMTPublic pubArea) {
        TPMGenerated magic = TPMGenerated.TPM_GENERATED_VALUE;
        TPMISTAttest type = TPMISTAttest.TPM_ST_ATTEST_CERTIFY;
        byte[] qualifiedSigner = Base64UrlUtil.decode("AAu8WfTf2aakLcO4Zq_y3w0Zgmu_AUtnqwrW67F2MGuABw");
        MessageDigest messageDigest;
        try {
            SignatureAlgorithm signatureAlgorithm = alg.toSignatureAlgorithm();
            messageDigest = signatureAlgorithm.getMessageDigestAlgorithm().createMessageDigestObject();
        } catch (IllegalArgumentException e) {
            throw new WebAuthnModelException("alg is not signature algorithm", e);
        }
        byte[] extraData = messageDigest.digest(attestationStatementRequest.getSignedData());
        BigInteger clock = BigInteger.valueOf(7270451399L);
        long resetCount = 1749088739L;
        long restartCount = 3639844613L;
        TPMSClockInfo clockInfo = new TPMSClockInfo(clock, resetCount, restartCount, true);
        BigInteger firmwareVersion = new BigInteger("12241000001210926099");
        byte[] nameDigest = MessageDigestUtil.createSHA256().digest(pubArea.getBytes());
        TPMTHA name = new TPMTHA(TPMIAlgHash.TPM_ALG_SHA256, nameDigest);
        byte[] qualifiedNameDigest = Base64UrlUtil.decode("AVI0eQ_AAZjNvrhUEMK2q4wxuwIFOnHIDF0Qljhf47Q");
        TPMTHA qualifiedName = new TPMTHA(TPMIAlgHash.TPM_ALG_SHA256, qualifiedNameDigest);
        TPMUAttest attested = new TPMSCertifyInfo(name, qualifiedName);

        return new TPMSAttest(magic, type, qualifiedSigner, extraData, clockInfo, firmwareVersion, attested);
    }

    private TPMTPublic createTPMTPublic(PublicKey credentialPublicKey) {
        TPMIAlgPublic type = null;
        TPMIAlgHash nameAlg = TPMIAlgHash.TPM_ALG_SHA256;
        TPMAObject objectAttributes = new TPMAObject(394354);
        byte[] authPolicy = Base64UrlUtil.decode("nf_L82w4OuaZ-5ho3G3LidcVOIS-KAOSLBJBWL-tIq4");
        TPMUPublicId unique = null;
        TPMUPublicParms parameters = null;
        if (credentialPublicKey instanceof ECPublicKey) {
            ECPublicKey ecPublicKey = (ECPublicKey) credentialPublicKey;
            EllipticCurve curve = ecPublicKey.getParams().getCurve();
            parameters = new TPMSECCParms(
                    new byte[2],
                    new byte[2],
                    TPMEccCurve.create(curve),
                    new byte[2]
            );
            type = TPMIAlgPublic.TPM_ALG_ECDSA;
            ECPoint ecPoint = ecPublicKey.getW();
            byte[] x = ecPoint.getAffineX().toByteArray();
            byte[] y = ecPoint.getAffineY().toByteArray();
            unique = new ECCUnique(x, y);
        }
        return new TPMTPublic(type, nameAlg, objectAttributes, authPolicy, parameters, unique);
    }
}
