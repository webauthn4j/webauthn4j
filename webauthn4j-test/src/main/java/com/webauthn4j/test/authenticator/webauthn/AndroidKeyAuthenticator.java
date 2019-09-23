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
import com.webauthn4j.test.AttestationCertificateBuilder;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.test.client.RegistrationEmulationOption;
import com.webauthn4j.validator.attestation.statement.androidkey.KeyDescriptionValidator;
import org.bouncycastle.asn1.*;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;

public class AndroidKeyAuthenticator extends WebAuthnModelAuthenticator {

    @Override
    public AttestationStatement createAttestationStatement(AttestationStatementRequest attestationStatementRequest, RegistrationEmulationOption registrationEmulationOption) {
        byte[] signature;
        if (registrationEmulationOption.isSignatureOverrideEnabled()) {
            signature = registrationEmulationOption.getSignature();
        } else {
            signature = TestDataUtil.calculateSignature(attestationStatementRequest.getCredentialKeyPair().getPrivate(), attestationStatementRequest.getSignedData());
        }
        AttestationOption attestationOption = registrationEmulationOption.getAttestationOption() == null ? new AndroidKeyAttestationOption() : registrationEmulationOption.getAttestationOption();
        X509Certificate attestationCertificate =
                getAttestationCertificate(attestationStatementRequest, attestationOption);

        AttestationCertificatePath attestationCertificates = new AttestationCertificatePath(attestationCertificate, this.getCACertificatePath());
        return new AndroidKeyAttestationStatement(COSEAlgorithmIdentifier.ES256, signature, attestationCertificates);
    }

    @Override
    protected X509Certificate createAttestationCertificate(AttestationStatementRequest attestationStatementRequest, AttestationOption attestationOption) {

        AttestationCertificateBuilder builder =
                new AttestationCertificateBuilder(
                        getAttestationIssuerCertificate(),
                        new X500Principal(attestationOption.getSubjectDN()),
                        attestationStatementRequest.getCredentialKeyPair().getPublic());

        builder.addExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"), false, createKeyDescriptor(attestationStatementRequest.getClientDataHash()));
        builder.addBasicConstraintsExtension();
        builder.addKeyUsageExtension();
        return builder.build(this.getAttestationIssuerPrivateKey());
    }

    private X509Certificate createAttestationCertificate(AttestationStatementRequest attestationStatementRequest) {
        return createAttestationCertificate(attestationStatementRequest, new AndroidKeyAttestationOption());
    }

    private ASN1Encodable createKeyDescriptor(byte[] clientDataHash) {
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
