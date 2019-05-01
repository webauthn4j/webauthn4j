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

import com.webauthn4j.data.attestation.statement.AndroidKeyAttestationStatement;
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.test.AttestationCertificateBuilder;
import com.webauthn4j.test.CertificateCreationOption;
import com.webauthn4j.test.TestAttestationUtil;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.test.client.RegistrationEmulationOption;
import com.webauthn4j.validator.attestation.statement.androidkey.KeyDescriptionValidator;
import org.bouncycastle.asn1.*;

import javax.security.auth.x500.X500Principal;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class AndroidKeyAuthenticator extends WebAuthnModelAuthenticator{

    @Override
    protected AttestationStatement createAttestationStatement(AttestationStatementRequest attestationStatementRequest, RegistrationEmulationOption registrationEmulationOption) {
        byte[] signature;
        if (registrationEmulationOption.isSignatureOverrideEnabled()) {
            signature = registrationEmulationOption.getSignature();
        } else {
            signature = TestDataUtil.calculateSignature(attestationStatementRequest.getCredentialKeyPair().getPrivate(), attestationStatementRequest.getSignedData());
        }
        X509Certificate attestationCertificate =
                createAttestationCertificate(
                        attestationStatementRequest.getCredentialKeyPair().getPublic(),
                        attestationStatementRequest.getClientDataHash());
        List<X509Certificate> list = new ArrayList<>();
        list.add(attestationCertificate);
        list.addAll(this.getCACertificatePath());
        AttestationCertificatePath attestationCertificates = new AttestationCertificatePath(list);
        return new AndroidKeyAttestationStatement(COSEAlgorithmIdentifier.ES256, signature, attestationCertificates);
    }

    public X509Certificate createAttestationCertificate(PublicKey credentialPublicKey, byte[] clientDataHash, CertificateCreationOption certificateCreationOption) {
        X509Certificate issuerCertificate = this.getCACertificatePath().get(0);
        switch (certificateCreationOption.getX509CertificateVersion()){
            case 1:
                return TestAttestationUtil.createV1DummyCertificate();
            case 3:
                break;
            default:
                throw new IllegalArgumentException("Only version 1 or 3 are supported.");
        }

        AttestationCertificateBuilder attestationCertificateBuilder = new AttestationCertificateBuilder(issuerCertificate, new X500Principal("O=SharpLab., C=US"), credentialPublicKey);

        attestationCertificateBuilder.addExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"), false, createKeyDescriptor(clientDataHash));
        attestationCertificateBuilder.addBasicConstraintsExtension();
        attestationCertificateBuilder.addKeyUsageExtension();
        return attestationCertificateBuilder.build(this.getAttestationIssuerPrivateKey());
    }

    public X509Certificate createAttestationCertificate(PublicKey publicKey, byte[] clientDataHash) {
        return createAttestationCertificate(publicKey, clientDataHash, new CertificateCreationOption());
    }

    public ASN1Encodable createKeyDescriptor(byte[] clientDataHash){
        ASN1Integer attestationVersion = new ASN1Integer(2);
        ASN1Enumerated attestationSecurityLevel = new ASN1Enumerated(0);
        ASN1Integer keymasterVersion = new ASN1Integer(1);
        ASN1Enumerated keymasterSecurityLevel = new ASN1Enumerated(0);
        DEROctetString attestationChallenge = new DEROctetString(clientDataHash);
        ASN1OctetString reserved = new DEROctetString(new byte[0]);

        ASN1EncodableVector softwareEnforcedVector = new ASN1EncodableVector();
        DLSequence softwareEnforced = new DLSequence(softwareEnforcedVector);

        ASN1EncodableVector teeEnforcedVector = new ASN1EncodableVector();
        teeEnforcedVector.add(new DERTaggedObject(KeyDescriptionValidator.KM_TAG_ORIGIN, new ASN1Integer(KeyDescriptionValidator.KM_ORIGIN_GENERATED)));
        teeEnforcedVector.add(new DERTaggedObject(KeyDescriptionValidator.KM_TAG_PURPOSE, new DERSet(new ASN1Integer(KeyDescriptionValidator.KM_PURPOSE_SIGN))));
        DLSequence teeEnforced = new DLSequence(teeEnforcedVector);

        ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();
        asn1EncodableVector.add(attestationVersion);
        asn1EncodableVector.add(attestationSecurityLevel);
        asn1EncodableVector.add(keymasterVersion);
        asn1EncodableVector.add(keymasterSecurityLevel);
        asn1EncodableVector.add(attestationChallenge);
        asn1EncodableVector.add(reserved);
        asn1EncodableVector.add(softwareEnforced);
        asn1EncodableVector.add(teeEnforced);

        return new DLSequence(asn1EncodableVector);
    }

}
