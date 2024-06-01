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

package com.webauthn4j.test;

import com.webauthn4j.util.exception.UnexpectedCheckedException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.time.Instant;

public class AttestationCertificateBuilder {

    private final X509v3CertificateBuilder certificateBuilder;

    public AttestationCertificateBuilder(X509Certificate issuerCertificate, X500Principal subject, PublicKey publicKey) {
        certificateBuilder = new JcaX509v3CertificateBuilder(
                issuerCertificate,
                BigInteger.valueOf(1),
                Date.from(Instant.parse("2000-01-01T00:00:00Z")),
                Date.from(Instant.parse("2999-12-31T23:59:59Z")),
                subject,
                publicKey
        );
    }

    public void addSubjectAlternativeNamesExtension(String subjectAlternativeNames) {
        try {
            DERSequence derSequence = new DERSequence(new ASN1Encodable[]{
                    new GeneralName(GeneralName.directoryName, subjectAlternativeNames)
            });
            certificateBuilder.addExtension(Extension.subjectAlternativeName, true, derSequence);
        } catch (CertIOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public void addBasicConstraintsExtension() {
        try {
            certificateBuilder.addExtension(
                    Extension.basicConstraints,
                    false,
                    new BasicConstraints(true)
            );
        } catch (CertIOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public void addKeyUsageExtension() {
        try {
            certificateBuilder.addExtension(
                    Extension.keyUsage, // Key Usage
                    false,
                    new KeyUsage(KeyUsage.keyCertSign)
            );
        } catch (CertIOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public void addExtendedKeyUsageExtension(KeyPurposeId keyPurposeId) {
        try {
            certificateBuilder.addExtension(
                    Extension.extendedKeyUsage, // Extended Key Usage
                    true,
                    new ExtendedKeyUsage(keyPurposeId) // tcg-kp-AIKCertificate OID
            );
        } catch (CertIOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public X509Certificate build(PrivateKey issuerPrivateKey) {
        try {
            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(issuerPrivateKey);
            X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);
            return new JcaX509CertificateConverter().getCertificate(certificateHolder);
        } catch (CertificateException e) {
            throw new com.webauthn4j.verifier.exception.CertificateException(e);
        } catch (OperatorCreationException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    public void addExtension(ASN1ObjectIdentifier oid, boolean isCritical, ASN1Encodable value) {
        try {
            certificateBuilder.addExtension(oid, isCritical, value);
        } catch (CertIOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
