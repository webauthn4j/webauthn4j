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

package com.webauthn4j.test.authenticator.webauthn;

import com.webauthn4j.data.attestation.statement.*;
import com.webauthn4j.test.*;
import com.webauthn4j.test.client.RegistrationEmulationOption;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.util.WIP;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyPurposeId;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.ArrayList;
import java.util.List;

@WIP
public class TPMAuthenticator extends WebAuthnModelAuthenticator {

    private PrivateKey attestationPrivateKey;
    private PublicKey attestationPublicKey = TestAttestationUtil.load3tierTestAuthenticatorAttestationPublicKey();
    private AttestationCertificatePath caCertificatePath;
    private X509Certificate attestationCertificate;
    private PrivateKey issuerPrivateKey = TestAttestationUtil.load3tierTestIntermediateCAPrivateKey();

    public TPMAuthenticator(PrivateKey attestationPrivateKey, AttestationCertificatePath caCertificatePath){
        super();
        this.attestationPrivateKey = attestationPrivateKey;
        this.caCertificatePath = caCertificatePath;
        this.attestationCertificate = createAttestationCertificate();
    }

    public TPMAuthenticator() {
        this(TestDataConstants.GENERIC_3TIER_ATTESTATION_PRIVATE_KEY, TestAttestationUtil.load3tierTestCACertPath());
    }

    @Override
    protected AttestationStatement createAttestationStatement(AttestationStatementRequest attestationStatementRequest, RegistrationEmulationOption registrationEmulationOption) {

        COSEAlgorithmIdentifier alg = COSEAlgorithmIdentifier.ES256;

        TPMTPublic pubArea = generateTPMTPublic(attestationStatementRequest.getCredentialKeyPair().getPublic());

        TPMGenerated magic = TPMGenerated.TPM_GENERATED_VALUE;
        TPMISTAttest type = TPMISTAttest.TPM_ST_ATTEST_CERTIFY;
        byte[] qualifiedSigner = Base64UrlUtil.decode("AAu8WfTf2aakLcO4Zq_y3w0Zgmu_AUtnqwrW67F2MGuABw");
        byte[] extraData = MessageDigestUtil.createMessageDigest(alg.getMessageDigestJcaName()).digest(attestationStatementRequest.getSignedData());
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

        TPMSAttest certInfo = new TPMSAttest(magic, type, qualifiedSigner, extraData, clockInfo, firmwareVersion, attested);

        byte[] signature;
        if (registrationEmulationOption.isSignatureOverrideEnabled()) {
            signature = registrationEmulationOption.getSignature();
        } else {
            signature = TestDataUtil.calculateSignature(attestationPrivateKey, certInfo.getBytes());
        }

        List<X509Certificate> attestationCertificates = new ArrayList<>();
        attestationCertificates.add(attestationCertificate);
        attestationCertificates.addAll(caCertificatePath);
        AttestationCertificatePath attestationCertificatePath = new AttestationCertificatePath(attestationCertificates);

        return new TPMAttestationStatement(alg, attestationCertificatePath, signature, certInfo, pubArea);
    }

    public X509Certificate createAttestationCertificate(CertificateCreationOption certificateCreationOption) {
        X509Certificate issuerCertificate = caCertificatePath.get(0);

        switch (certificateCreationOption.getX509CertificateVersion()){
            case 1:
                return TestAttestationUtil.createV1DummyCertificate();
            case 3:
                break;
            default:
                throw new IllegalArgumentException("Only version 1 or 3 are supported.");
        }

        AttestationCertificateBuilder builder = new AttestationCertificateBuilder(
                issuerCertificate,
                new X500Principal(certificateCreationOption.getSubjectDN()),
                attestationPublicKey
        );
        builder.addSubjectAlternativeNamesExtension("2.23.133.2.3=#0c0b69643a3030303230303030,2.23.133.2.2=#0c03535054,2.23.133.2.1=#0c0b69643a3439344535343433");
        if(certificateCreationOption.isCAFlagInBasicConstraints()){
            builder.addBasicConstraintsExtension();
        }
        if(certificateCreationOption.isTcgKpAIKCertificateFlagInExtendedKeyUsage()){
            builder.addExtendedKeyUsageExtension(KeyPurposeId.getInstance(new ASN1ObjectIdentifier("2.23.133.8.3")));
        }
        return builder.build(issuerPrivateKey);
    }

    public X509Certificate createAttestationCertificate() {
        return createAttestationCertificate(new CertificateCreationOption());
    }

    private TPMTPublic generateTPMTPublic(PublicKey credentialPublicKey) {
        TPMIAlgPublic type = null;
        TPMIAlgHash nameAlg = TPMIAlgHash.TPM_ALG_SHA256;
        TPMAObject objectAttributes = new TPMAObject(394354);
        byte[] authPolicy = Base64UrlUtil.decode("nf_L82w4OuaZ-5ho3G3LidcVOIS-KAOSLBJBWL-tIq4");
        TPMUPublicId unique = null;
        TPMUPublicParms parameters = null;
        if(credentialPublicKey instanceof ECPublicKey) {
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
