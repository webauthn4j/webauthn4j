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

package com.webauthn4j.metadata;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.metadata.data.MetadataBLOB;
import com.webauthn4j.metadata.data.MetadataBLOBFactory;
import com.webauthn4j.metadata.exception.MDSException;
import com.webauthn4j.util.CertificateUtil;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.*;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

/**
 * Load MetadataBLOB from a local file. This provider validates MetadataBLOB signature.
 */
public class FidoMDS3MetadataBLOBProvider extends CachingMetadataBLOBProvider{

    private static final String DEFAULT_BLOB_ENDPOINT = "https://mds.fidoalliance.org/";

    private final MetadataBLOBFactory metadataBLOBFactory;
    private final String blobEndpoint;
    private final HttpClient httpClient;
    private final Set<TrustAnchor> trustAnchors;
    private boolean revocationCheckEnabled = true;

    public FidoMDS3MetadataBLOBProvider(@NonNull ObjectConverter objectConverter, @NonNull String blobEndpoint, @NonNull HttpClient httpClient, @NonNull Set<TrustAnchor> trustAnchors) {
        this.metadataBLOBFactory = new MetadataBLOBFactory(objectConverter);
        this.blobEndpoint = blobEndpoint;
        this.httpClient = httpClient;
        this.trustAnchors = trustAnchors;
    }

    public FidoMDS3MetadataBLOBProvider(@NonNull ObjectConverter objectConverter, @NonNull String blobEndpoint, @NonNull Set<TrustAnchor> trustAnchors) {
        this(objectConverter, blobEndpoint, new SimpleHttpClient(), trustAnchors);
    }

    public FidoMDS3MetadataBLOBProvider(@NonNull ObjectConverter objectConverter, @NonNull String blobEndpoint, @NonNull X509Certificate trustAnchorCertificate) {
        this(objectConverter, blobEndpoint, new SimpleHttpClient(), Collections.singleton(new TrustAnchor(trustAnchorCertificate, null)));
    }

    public FidoMDS3MetadataBLOBProvider(@NonNull ObjectConverter objectConverter, @NonNull Set<TrustAnchor> trustAnchors) {
        this(objectConverter, DEFAULT_BLOB_ENDPOINT, trustAnchors);
    }

    public FidoMDS3MetadataBLOBProvider(@NonNull ObjectConverter objectConverter, @NonNull X509Certificate trustAnchorCertificate) {
        this(objectConverter, DEFAULT_BLOB_ENDPOINT, Collections.singleton(new TrustAnchor(trustAnchorCertificate, null)));
    }

    @Override
    protected @NonNull MetadataBLOB doProvide() {
        String responseBody = httpClient.fetch(blobEndpoint);
        MetadataBLOB metadataBLOB = metadataBLOBFactory.parse(responseBody);
        if(!metadataBLOB.isValidSignature()){
            throw new MDSException("MetadataBLOB signature is invalid");
        }
        validateCertPath(metadataBLOB);
        return metadataBLOB;
    }

    private void validateCertPath(@NonNull MetadataBLOB metadataBLOB) {
        CertPath certPath = metadataBLOB.getHeader().getX5c();

        CertPathValidator certPathValidator = CertificateUtil.createCertPathValidator();
        PKIXParameters certPathParameters = CertificateUtil.createPKIXParameters(trustAnchors);
        certPathParameters.setRevocationEnabled(revocationCheckEnabled);
        PKIXRevocationChecker pkixRevocationChecker = (PKIXRevocationChecker) certPathValidator.getRevocationChecker();
        pkixRevocationChecker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.PREFER_CRLS));
        certPathParameters.addCertPathChecker(pkixRevocationChecker);

        try {
            certPathValidator.validate(certPath, certPathParameters);
        } catch (InvalidAlgorithmParameterException e) {
            throw new MDSException("invalid algorithm parameter", e);
        } catch (CertPathValidatorException e) {
            throw new MDSException("invalid cert path", e);
        }
    }

    public boolean isRevocationCheckEnabled() {
        return revocationCheckEnabled;
    }

    public void setRevocationCheckEnabled(boolean revocationCheckEnabled) {
        this.revocationCheckEnabled = revocationCheckEnabled;
    }
}
