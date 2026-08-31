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

package com.webauthn4j.async.metadata;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.metadata.CertPathCheckContext;
import com.webauthn4j.metadata.data.MetadataBLOB;
import com.webauthn4j.metadata.data.MetadataBLOBFactory;
import com.webauthn4j.metadata.exception.CertPathCheckException;
import com.webauthn4j.metadata.exception.MDSException;
import com.webauthn4j.metadata.util.internal.DefaultCertPathChecker;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.security.cert.CertPath;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * Load MetadataBLOB from the FIDO Alliance Metadata Service. This provider validates MetadataBLOB signature.
 */
public class FidoMDS3MetadataBLOBAsyncProvider extends CachingMetadataBLOBAsyncProvider {

    public static final String DEFAULT_BLOB_ENDPOINT = "https://mds.fidoalliance.org/";

    private static final Executor DEFAULT_CERT_PATH_VALIDATION_EXECUTOR =
            Executors.newSingleThreadExecutor(runnable -> {
                Thread thread = new Thread(runnable, "webauthn4j-mds-cert-path-validation");
                thread.setDaemon(true);
                return thread;
            });

    private final MetadataBLOBFactory metadataBLOBFactory;
    private final String blobEndpoint;
    private final HttpAsyncClient httpClient;
    private final Set<TrustAnchor> trustAnchors;
    private boolean revocationCheckEnabled = true;
    private CertPathAsyncChecker certPathAsyncChecker;

    public FidoMDS3MetadataBLOBAsyncProvider(@NotNull ObjectConverter objectConverter, @NotNull String blobEndpoint, @NotNull HttpAsyncClient httpClient, @NotNull Set<TrustAnchor> trustAnchors, @NotNull Executor certPathValidationExecutor) {
        this.metadataBLOBFactory = new MetadataBLOBFactory(objectConverter);
        this.blobEndpoint = blobEndpoint;
        this.httpClient = httpClient;
        this.trustAnchors = trustAnchors;
        this.certPathAsyncChecker = new DefaultCertPathAsyncChecker(certPathValidationExecutor);
    }

    public FidoMDS3MetadataBLOBAsyncProvider(@NotNull ObjectConverter objectConverter, @NotNull String blobEndpoint, @NotNull HttpAsyncClient httpClient, @NotNull Set<TrustAnchor> trustAnchors) {
        this(objectConverter, blobEndpoint, httpClient, trustAnchors, DEFAULT_CERT_PATH_VALIDATION_EXECUTOR);
    }

    public FidoMDS3MetadataBLOBAsyncProvider(@NotNull ObjectConverter objectConverter, @NotNull String blobEndpoint, @NotNull Set<TrustAnchor> trustAnchors) {
        this(objectConverter, blobEndpoint, new SimpleHttpAsyncClient(), trustAnchors);
    }

    public FidoMDS3MetadataBLOBAsyncProvider(@NotNull ObjectConverter objectConverter, @NotNull String blobEndpoint, @NotNull X509Certificate trustAnchorCertificate) {
        this(objectConverter, blobEndpoint, new SimpleHttpAsyncClient(), Collections.singleton(new TrustAnchor(trustAnchorCertificate, null)));
    }

    public FidoMDS3MetadataBLOBAsyncProvider(@NotNull ObjectConverter objectConverter, @NotNull Set<TrustAnchor> trustAnchors) {
        this(objectConverter, DEFAULT_BLOB_ENDPOINT, trustAnchors);
    }

    public FidoMDS3MetadataBLOBAsyncProvider(@NotNull ObjectConverter objectConverter, @NotNull X509Certificate trustAnchorCertificate) {
        this(objectConverter, DEFAULT_BLOB_ENDPOINT, Collections.singleton(new TrustAnchor(trustAnchorCertificate, null)));
    }

    @Override
    protected @NotNull CompletionStage<MetadataBLOB> doProvide() {
        return httpClient.fetch(blobEndpoint).thenApply(response -> {
            String body = readAsString(response.getBody());
            return metadataBLOBFactory.parse(body);
        }).thenCompose(metadataBLOB -> {
            if(!metadataBLOB.isValidSignature()){
                throw new MDSException("MetadataBLOB signature is invalid");
            }
            return validateCertPath(metadataBLOB).thenApply(unused -> metadataBLOB);
        });
    }

    private static @NotNull String readAsString(InputStream responseBody) {
        try {
            return new String(responseBody.readAllBytes());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private CompletionStage<Void> validateCertPath(@NotNull MetadataBLOB metadataBLOB) {
        CertPath certPath = metadataBLOB.getHeader().getX5c();
        try{
            return certPathAsyncChecker.check(new CertPathCheckContext(certPath, trustAnchors, isRevocationCheckEnabled()));
        }
        catch (CertPathCheckException e){
            throw new MDSException("MetadataBLOB certificate chain validation failed", e);
        }
    }

    public boolean isRevocationCheckEnabled() {
        return revocationCheckEnabled;
    }

    public void setRevocationCheckEnabled(boolean revocationCheckEnabled) {
        this.revocationCheckEnabled = revocationCheckEnabled;
    }

    public CertPathAsyncChecker getCertPathAsyncValidator() {
        return certPathAsyncChecker;
    }

    public void setCertPathAsyncValidator(CertPathAsyncChecker certPathAsyncChecker) {
        this.certPathAsyncChecker = certPathAsyncChecker;
    }

    private static class DefaultCertPathAsyncChecker implements CertPathAsyncChecker {

        private final Executor executor;
        private final DefaultCertPathChecker delegate = new DefaultCertPathChecker();

        public DefaultCertPathAsyncChecker(Executor executor){
            this.executor = executor;
        }

        @Override
        public CompletionStage<Void> check(CertPathCheckContext context) throws MDSException {
            return CompletableFuture.completedStage(null)
                    .thenCompose(unused -> CompletableFuture.runAsync(() -> delegate.check(context), executor));
        }
    }
}
