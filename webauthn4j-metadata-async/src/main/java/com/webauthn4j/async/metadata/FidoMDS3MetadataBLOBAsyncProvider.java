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
import com.webauthn4j.util.CertificateUtil;
import com.webauthn4j.verifier.internal.asn1.ASN1;
import com.webauthn4j.verifier.internal.asn1.ASN1Primitive;
import com.webauthn4j.verifier.internal.asn1.ASN1Structure;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URL;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Load MetadataBLOB from a local file. This provider validates MetadataBLOB signature.
 */
public class FidoMDS3MetadataBLOBAsyncProvider extends CachingMetadataBLOBAsyncProvider {

    public static final String DEFAULT_BLOB_ENDPOINT = "https://mds.fidoalliance.org/";

    private final MetadataBLOBFactory metadataBLOBFactory;
    private final String blobEndpoint;
    private final HttpAsyncClient httpClient;
    private final Set<TrustAnchor> trustAnchors;
    private boolean revocationCheckEnabled = true;
    private CertPathAsyncChecker certPathAsyncChecker;

    public FidoMDS3MetadataBLOBAsyncProvider(@NotNull ObjectConverter objectConverter, @NotNull String blobEndpoint, @NotNull HttpAsyncClient httpClient, @NotNull Set<TrustAnchor> trustAnchors) {
        this.metadataBLOBFactory = new MetadataBLOBFactory(objectConverter);
        this.blobEndpoint = blobEndpoint;
        this.httpClient = httpClient;
        this.trustAnchors = trustAnchors;
        this.certPathAsyncChecker = new DefaultCertPathAsyncChecker(httpClient);
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

        private final HttpAsyncClient httpClient;

        public DefaultCertPathAsyncChecker(HttpAsyncClient httpClient){
            this.httpClient = httpClient;
        }

        @Override
        public CompletionStage<Void> check(CertPathCheckContext context) throws MDSException {
            CertPathValidator certPathValidator = CertificateUtil.createCertPathValidator();
            PKIXParameters certPathParameters = CertificateUtil.createPKIXParameters(context.getTrustAnchors());
            certPathParameters.setRevocationEnabled(false); //This validator uses checkCRL, which is our own (async) revocation check.
            try {
                certPathValidator.validate(context.getCertPath(), certPathParameters);
            } catch (InvalidAlgorithmParameterException e) {
                throw new CertPathCheckException("invalid algorithm parameter", e);
            } catch (CertPathValidatorException e) {
                throw new CertPathCheckException("invalid cert path", e);
            }

            if(context.isRevocationCheckEnabled()){
                return checkCRL(context);
            }
            else{
                return CompletableFuture.completedFuture(null);
            }
        }

        private CompletionStage<Void> checkCRL(CertPathCheckContext context) {
            List<X509Certificate> certPathToTrustAnchor = new ArrayList<>();
            context.getCertPath().getCertificates().forEach(cert -> certPathToTrustAnchor.add((X509Certificate) cert));
            X509Certificate last = certPathToTrustAnchor.get(certPathToTrustAnchor.size()-1);
            TrustAnchor trustAnchor = context.getTrustAnchors().stream().filter(item -> Objects.equals(item.getTrustedCert().getSubjectX500Principal(), last.getIssuerX500Principal())).findFirst().orElseThrow();
            certPathToTrustAnchor.add(trustAnchor.getTrustedCert());


            Stream<CompletionStage<Void>> completionStageStream = context.getCertPath().getCertificates().stream().map(certificate -> {
                X509Certificate x509Certificate = (X509Certificate) certificate;
                List<String> crlDistributionPoints = extractCRLDistributionPoints(x509Certificate);
                Stream<CompletionStage<X509CRL>> crlCompletionStageStream = crlDistributionPoints.stream().map(this::fetchCRL);
                return join(crlCompletionStageStream).thenApply(crlStream -> {
                    crlStream.forEach(crl -> {
                        try {
                            X509Certificate crlIssuerCertificate = certPathToTrustAnchor.stream().filter(cert -> Objects.equals(cert.getSubjectX500Principal(), crl.getIssuerX500Principal())).findFirst().orElseThrow();
                            crl.verify(crlIssuerCertificate.getPublicKey());
                        } catch (CRLException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException e) {
                            throw new CertPathCheckException("crl validation failed", e);
                        }
                        if(crl.isRevoked(certificate)){
                            throw new CertPathCheckException("Certificate is revoked");
                        }
                    });
                    return null;
                });
            });

            return join(completionStageStream).thenApply(stream -> null);
        }

        private static <T> CompletionStage<Stream<T>> join(Stream<CompletionStage<T>> completionStages) {
            List<CompletableFuture<T>> completableFutures = completionStages.map(CompletionStage::toCompletableFuture).collect(Collectors.toList());
            CompletableFuture<?>[] array = completableFutures.toArray(CompletableFuture[]::new);
            CompletableFuture<Void> joinedFuture = CompletableFuture.allOf(array);
            return joinedFuture.thenApply(unused -> completableFutures.stream().map(CompletableFuture::join));
        }

        private CompletionStage<X509CRL> fetchCRL(String crlDistributionPoint){
            try {
                URL url = new URL(crlDistributionPoint);
                if(url.getProtocol().equals("http") || url.getProtocol().equals("https")) {
                    return httpClient.fetch(crlDistributionPoint).thenApply( response -> {
                        if(response.getStatusCode() >= 400){
                            throw new CertPathCheckException(String.format("Failed to fetch CRL. HTTP Status code: %d", response.getStatusCode()));
                        }
                        CertificateFactory certificateFactory = CertificateUtil.createCertificateFactory();
                        try {
                            return (X509CRL)certificateFactory.generateCRL(response.getBody());
                        }
                        catch (CRLException e) {
                            throw new CertPathCheckException(e);
                        }
                    });
                }
                else {
                    throw new CertPathCheckException("http or https is the only supported protocol to fetch CRL.");
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }

        @SuppressWarnings("java:S1155")
        private List<String> extractCRLDistributionPoints(X509Certificate x509Certificate){
            byte[] extensionValue = x509Certificate.getExtensionValue("2.5.29.31");

            ASN1Primitive envelope = ASN1Primitive.parse(extensionValue);
            ASN1Structure crlDistributionPoints = envelope.getValueAsASN1Structure();
            ArrayList<String> urls = new ArrayList<>();
            for (ASN1 item: crlDistributionPoints){
                ASN1Structure distributionPointSequence = (ASN1Structure)item;
                ASN1Structure distributionPoint = (ASN1Structure) distributionPointSequence.get(0);
                ASN1Structure fullName = (ASN1Structure)distributionPoint.get(0);
                for (ASN1 fullNameItem : fullName){
                    String url = ((ASN1Primitive)fullNameItem).getValueAsUtf8String();
                    urls.add(url);
                }
            }

            return Collections.unmodifiableList(urls);
        }
    }
}
