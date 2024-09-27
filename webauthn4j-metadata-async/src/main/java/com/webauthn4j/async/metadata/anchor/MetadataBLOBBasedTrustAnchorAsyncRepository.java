package com.webauthn4j.async.metadata.anchor;

import com.webauthn4j.async.anchor.TrustAnchorAsyncRepository;
import com.webauthn4j.async.metadata.MetadataBLOBAsyncProvider;
import com.webauthn4j.async.metadata.MetadataBLOBBasedMetadataStatementAsyncRepository;
import com.webauthn4j.data.attestation.authenticator.AAGUID;

import java.security.cert.TrustAnchor;
import java.util.Set;
import java.util.concurrent.CompletionStage;
import java.util.stream.Collectors;

public class MetadataBLOBBasedTrustAnchorAsyncRepository implements TrustAnchorAsyncRepository {

    private final MetadataBLOBBasedMetadataStatementAsyncRepository metadataBLOBBasedMetadataStatementAsyncRepository;

    public MetadataBLOBBasedTrustAnchorAsyncRepository(MetadataBLOBAsyncProvider... metadataBLOBAsyncProviders) {
        this.metadataBLOBBasedMetadataStatementAsyncRepository = new MetadataBLOBBasedMetadataStatementAsyncRepository(metadataBLOBAsyncProviders);
    }

    @Override
    public CompletionStage<Set<TrustAnchor>> find(AAGUID aaguid) {
        return metadataBLOBBasedMetadataStatementAsyncRepository.find(aaguid).thenApply(metadataStatements-> metadataStatements.stream()
                .flatMap(item -> item.getAttestationRootCertificates().stream())
                .map(item -> new TrustAnchor(item, null))
                .collect(Collectors.toSet()));
    }

    @Override
    public CompletionStage<Set<TrustAnchor>> find(byte[] attestationCertificateKeyIdentifier) {
        return metadataBLOBBasedMetadataStatementAsyncRepository.find(attestationCertificateKeyIdentifier).thenApply(metadataStatements -> metadataStatements.stream()
                .flatMap(item -> item.getAttestationRootCertificates().stream())
                .map(item -> new TrustAnchor(item, null))
                .collect(Collectors.toSet()));
    }

    public boolean isNotFidoCertifiedAllowed() {
        return metadataBLOBBasedMetadataStatementAsyncRepository.isNotFidoCertifiedAllowed();
    }

    public void setNotFidoCertifiedAllowed(boolean notFidoCertifiedAllowed) {
        metadataBLOBBasedMetadataStatementAsyncRepository.setNotFidoCertifiedAllowed(notFidoCertifiedAllowed);
    }

    public boolean isSelfAssertionSubmittedAllowed() {
        return metadataBLOBBasedMetadataStatementAsyncRepository.isSelfAssertionSubmittedAllowed();
    }

    public void setSelfAssertionSubmittedAllowed(boolean selfAssertionSubmittedAllowed) {
        metadataBLOBBasedMetadataStatementAsyncRepository.setSelfAssertionSubmittedAllowed(selfAssertionSubmittedAllowed);
    }

}
