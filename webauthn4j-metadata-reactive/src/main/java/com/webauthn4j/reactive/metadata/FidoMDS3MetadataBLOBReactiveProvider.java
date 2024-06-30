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

package com.webauthn4j.reactive.metadata;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.metadata.CertPathCheckContext;
import com.webauthn4j.metadata.data.MetadataBLOB;
import com.webauthn4j.metadata.data.MetadataBLOBFactory;
import com.webauthn4j.metadata.exception.CertPathCheckException;
import com.webauthn4j.metadata.exception.MDSException;
import com.webauthn4j.util.CertificateUtil;
import com.webauthn4j.util.exception.NotImplementedException;
import org.apache.kerby.asn1.parse.Asn1Container;
import org.apache.kerby.asn1.parse.Asn1ParseResult;
import org.apache.kerby.asn1.parse.Asn1Parser;
import org.apache.kerby.asn1.type.Asn1GeneralString;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.jetbrains.annotations.NotNull;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Load MetadataBLOB from a local file. This provider validates MetadataBLOB signature.
 */
public class FidoMDS3MetadataBLOBReactiveProvider extends CachingMetadataBLOBReactiveProvider {

    public static final String DEFAULT_BLOB_ENDPOINT = "https://mds.fidoalliance.org/";

    private final MetadataBLOBFactory metadataBLOBFactory;
    private final String blobEndpoint;
    private final HttpReactiveClient httpClient;
    private final Set<TrustAnchor> trustAnchors;
    private boolean revocationCheckEnabled = true;
    private CertPathReactiveChecker certPathReactiveChecker;

    public FidoMDS3MetadataBLOBReactiveProvider(@NotNull ObjectConverter objectConverter, @NotNull String blobEndpoint, @NotNull HttpReactiveClient httpClient, @NotNull Set<TrustAnchor> trustAnchors) {
        this.metadataBLOBFactory = new MetadataBLOBFactory(objectConverter);
        this.blobEndpoint = blobEndpoint;
        this.httpClient = httpClient;
        this.trustAnchors = trustAnchors;
        this.certPathReactiveChecker = new DefaultCertPathReactiveChecker(httpClient);
    }

    public FidoMDS3MetadataBLOBReactiveProvider(@NotNull ObjectConverter objectConverter, @NotNull String blobEndpoint, @NotNull Set<TrustAnchor> trustAnchors) {
        this(objectConverter, blobEndpoint, new SimpleHttpReactiveClient(), trustAnchors);
    }

    public FidoMDS3MetadataBLOBReactiveProvider(@NotNull ObjectConverter objectConverter, @NotNull String blobEndpoint, @NotNull X509Certificate trustAnchorCertificate) {
        this(objectConverter, blobEndpoint, new SimpleHttpReactiveClient(), Collections.singleton(new TrustAnchor(trustAnchorCertificate, null)));
    }

    public FidoMDS3MetadataBLOBReactiveProvider(@NotNull ObjectConverter objectConverter, @NotNull Set<TrustAnchor> trustAnchors) {
        this(objectConverter, DEFAULT_BLOB_ENDPOINT, trustAnchors);
    }

    public FidoMDS3MetadataBLOBReactiveProvider(@NotNull ObjectConverter objectConverter, @NotNull X509Certificate trustAnchorCertificate) {
        this(objectConverter, DEFAULT_BLOB_ENDPOINT, Collections.singleton(new TrustAnchor(trustAnchorCertificate, null)));
    }

    @Override
    protected @NotNull CompletionStage<MetadataBLOB> doProvide() {
        return httpClient.fetch(blobEndpoint).thenApply((responseBody) -> {
            String body = readAsString(responseBody);
            MetadataBLOB metadataBLOB = metadataBLOBFactory.parse(body);
            if(!metadataBLOB.isValidSignature()){
                throw new MDSException("MetadataBLOB signature is invalid");
            }
            validateCertPath(metadataBLOB);
            return metadataBLOB;
        });
    }

    private static @NotNull String readAsString(InputStream responseBody) {
        try {
            return new String(responseBody.readAllBytes());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private void validateCertPath(@NotNull MetadataBLOB metadataBLOB) {
        CertPath certPath = metadataBLOB.getHeader().getX5c();
        try{
            certPathReactiveChecker.check(new CertPathCheckContext(certPath, trustAnchors, isRevocationCheckEnabled()));
        }
        catch (CertPathCheckException e){
            throw new MDSException("MetadataBLOB certificate chain validation failed");
        }
    }

    public boolean isRevocationCheckEnabled() {
        return revocationCheckEnabled;
    }

    public void setRevocationCheckEnabled(boolean revocationCheckEnabled) {
        this.revocationCheckEnabled = revocationCheckEnabled;
    }

    public CertPathReactiveChecker getCertPathReactiveValidator() {
        return certPathReactiveChecker;
    }

    public void setCertPathReactiveValidator(CertPathReactiveChecker certPathReactiveChecker) {
        this.certPathReactiveChecker = certPathReactiveChecker;
    }

    private static class DefaultCertPathReactiveChecker implements CertPathReactiveChecker {

        private final HttpReactiveClient httpClient;

        public DefaultCertPathReactiveChecker(HttpReactiveClient httpClient){
            this.httpClient = httpClient;
        }

        @Override
        public CompletionStage<Void> check(CertPathCheckContext context) throws MDSException {
            CertPathValidator certPathValidator = CertificateUtil.createCertPathValidator();
            PKIXParameters certPathParameters = CertificateUtil.createPKIXParameters(context.getTrustAnchors());
            certPathParameters.setRevocationEnabled(false); //This validator uses it own revocation check.
            try {
                certPathValidator.validate(context.getCertPath(), certPathParameters);
            } catch (InvalidAlgorithmParameterException e) {
                throw new CertPathCheckException("invalid algorithm parameter", e);
            } catch (CertPathValidatorException e) {
                throw new CertPathCheckException("invalid cert path", e);
            }

            if(context.isRevocationCheckEnabled()){
                Stream<CompletionStage<Void>> completionStageStream = context.getCertPath().getCertificates().stream().map(certificate -> {
                    X509Certificate x509Certificate = (X509Certificate) certificate;
                    List<String> crlDistributionPoints = extractCRLDistributionPoints(x509Certificate);
                    Stream<CompletionStage<X509CRL>> crlCompletionStageStream = crlDistributionPoints.stream().map(this::fetchCRL);
                    return join(crlCompletionStageStream).thenCompose(crls -> {
                        crls.forEach(crl -> {
                            //TODO: CRL trustworthiness verification
                            //crl.verify(caCert.getPublicKey());
                            if(crl.isRevoked(certificate)){
                                throw new CertPathCheckException("Certificate is revoked");
                            }
                        });
                        return CompletableFuture.completedFuture(null);
                    });
                });

                return join(completionStageStream).thenCompose(stream -> null);
            }
            else{
                return CompletableFuture.completedFuture(null);
            }
        }

        private static <T> CompletionStage<Stream<T>> join(Stream<CompletionStage<T>> completionStages) {
            List<CompletableFuture<T>> completableFutures = completionStages.map(CompletionStage::toCompletableFuture).collect(Collectors.toList());
            CompletableFuture<?>[] array = completableFutures.toArray(CompletableFuture[]::new);
            CompletableFuture<Void> joinedFuture = CompletableFuture.allOf(array);
            return joinedFuture.thenApply(__ -> completableFutures.stream().map(CompletableFuture::join));
        }

        private CompletionStage<X509CRL> fetchCRL(String crlDistributionPoint){
            try {
                URL url = new URL(crlDistributionPoint);
                if(url.getProtocol().equals("http") || url.getProtocol().equals("https")) {
                    return httpClient.fetch(crlDistributionPoint).thenApply( inputStream -> {
                        CertificateFactory certificateFactory = CertificateUtil.createCertificateFactory();
                        try {
                            return (X509CRL)certificateFactory.generateCRL(inputStream);
                        }
                        catch (CRLException e) {
                            throw new CertPathCheckException(e);
                        }
                    });
                }
                else {
                    throw new CertPathCheckException("http or https is the only supported protocol to fetch CRL.");
                }
            }
            catch (MalformedURLException e) {
                throw new CertPathCheckException("invalid crl distribution point URL", e);
            }
        }

        private List<String> extractCRLDistributionPoints(X509Certificate x509Certificate){
            try {
                byte[] extensionValue = x509Certificate.getExtensionValue("2.5.29.31");
                Asn1OctetString extensionEnvelope = new Asn1OctetString();
                extensionEnvelope.decode(extensionValue);
                byte[] extensionEnvelopeValue = extensionEnvelope.getValue();
                Asn1Container container = (Asn1Container) Asn1Parser.parse(ByteBuffer.wrap(extensionEnvelopeValue));
                var distributionPoints = container.getChildren();
                List<String> crlDistributionPoints = new ArrayList<>();
                for (Asn1ParseResult distributionPoint : distributionPoints) {
                    var list = ((Asn1Container) distributionPoint).getChildren();
                    //noinspection SizeReplaceableByIsEmpty
                    if (list.size() > 0) {
                        var distributionPointName = list.get(0);
                        Asn1GeneralString asn1GeneralString = new Asn1GeneralString();
                        asn1GeneralString.decode(distributionPointName.readBodyBytes());
                        crlDistributionPoints.add(asn1GeneralString.getValue());
                    }
                }
                return Collections.unmodifiableList(crlDistributionPoints);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    }
}
