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

package com.webauthn4j.util;

import com.webauthn4j.util.exception.UnexpectedCheckedException;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * A Utility class for metadata.certs
 */
public class CertificateUtil {

    private static CertificateFactory certificateFactory;

    private CertificateUtil() {
    }

    static {
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    public static CertPathValidator createCertPathValidator() {
        try {
            return CertPathValidator.getInstance("PKIX");
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    public static PKIXParameters createPKIXParameters(Set<TrustAnchor> trustAnchors) {
        AssertUtil.notEmpty(trustAnchors, "trustAnchors is required; it must not be empty");
        try {
            return new PKIXParameters(trustAnchors);
        } catch (InvalidAlgorithmParameterException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    public static KeyStore createKeyStore() {
        try {
            return KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    public static Set<TrustAnchor> generateTrustAnchors(List<X509Certificate> certificates){
        return certificates.stream().map( certificate -> new TrustAnchor(certificate, null)).collect(Collectors.toSet());
    }

    public static CertPath generateCertPath(List<Certificate> certificates) {
        try {
            return certificateFactory.generateCertPath(certificates);
        } catch (CertificateException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static X509Certificate generateX509Certificate(byte[] bytes) {
        return generateX509Certificate(new ByteArrayInputStream(bytes));
    }

    public static X509Certificate generateX509Certificate(InputStream inputStream) {
        try {
            return (X509Certificate) certificateFactory.generateCertificate(inputStream);
        } catch (CertificateException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static boolean isSelfSigned(X509Certificate certificate) {
        Signature signature = SignatureUtil.createSignature(certificate.getSigAlgName());
        try {
            signature.initVerify(certificate.getPublicKey());
        } catch (InvalidKeyException e) {
            return false;
        }
        try {
            signature.update(certificate.getPublicKey().getEncoded());
            signature.verify(certificate.getSignature());
        } catch (SignatureException e) {
            return false;
        }
        return true;
    }

}
