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

package com.webauthn4j.util;

import com.webauthn4j.util.exception.UnexpectedCheckedException;
import org.jetbrains.annotations.NotNull;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * A Utility class for certificate manipulation
 */
public class CertificateUtil {

    private static final CertificateFactory certificateFactory;

    static {
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    private CertificateUtil() {
    }

    public static @NotNull CertPathValidator createCertPathValidator() {
        try {
            return CertPathValidator.getInstance("PKIX");
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    public static @NotNull PKIXParameters createPKIXParameters(@NotNull Set<TrustAnchor> trustAnchors) {
        AssertUtil.notEmpty(trustAnchors, "trustAnchors is required; it must not be empty");
        try {
            return new PKIXParameters(trustAnchors);
        } catch (InvalidAlgorithmParameterException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    public static @NotNull KeyStore createKeyStore() {
        try {
            return KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    public static @NotNull CertificateFactory createCertificateFactory() {
        try {
            return CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    public static @NotNull <C extends X509Certificate> Set<TrustAnchor> generateTrustAnchors(@NotNull List<C> certificates) {
        return certificates.stream().map(certificate -> new TrustAnchor(certificate, null)).collect(Collectors.toSet());
    }

    public static @NotNull <C extends Certificate> CertPath generateCertPath(@NotNull List<C> certificates) {
        try {
            return certificateFactory.generateCertPath(certificates);
        } catch (CertificateException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static @NotNull X509Certificate generateX509Certificate(@NotNull byte[] bytes) {
        return generateX509Certificate(new ByteArrayInputStream(bytes));
    }

    public static @NotNull X509Certificate generateX509Certificate(@NotNull InputStream inputStream) {
        try {
            return (X509Certificate) certificateFactory.generateCertificate(inputStream);
        } catch (CertificateException e) {
            throw new IllegalArgumentException(e);
        }
    }



}
