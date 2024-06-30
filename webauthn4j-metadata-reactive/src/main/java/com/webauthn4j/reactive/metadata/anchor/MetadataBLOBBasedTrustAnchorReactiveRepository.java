package com.webauthn4j.reactive.metadata.anchor;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.reactive.anchor.TrustAnchorReactiveRepository;
import com.webauthn4j.reactive.metadata.MetadataBLOBBasedMetadataStatementReactiveRepository;
import com.webauthn4j.reactive.metadata.MetadataBLOBReactiveProvider;

import java.security.cert.TrustAnchor;
import java.util.Set;
import java.util.concurrent.CompletionStage;
import java.util.stream.Collectors;

public class MetadataBLOBBasedTrustAnchorReactiveRepository implements TrustAnchorReactiveRepository {

    private final MetadataBLOBBasedMetadataStatementReactiveRepository metadataBLOBBasedMetadataStatementReactiveRepository;

    public MetadataBLOBBasedTrustAnchorReactiveRepository(MetadataBLOBReactiveProvider... metadataBLOBReactiveProviders) {
        this.metadataBLOBBasedMetadataStatementReactiveRepository = new MetadataBLOBBasedMetadataStatementReactiveRepository(metadataBLOBReactiveProviders);
    }

    @Override
    public CompletionStage<Set<TrustAnchor>> find(AAGUID aaguid) {
        return metadataBLOBBasedMetadataStatementReactiveRepository.find(aaguid).thenApply(metadataStatements-> metadataStatements.stream()
                .flatMap(item -> item.getAttestationRootCertificates().stream())
                .map(item -> new TrustAnchor(item, null))
                .collect(Collectors.toSet()));
    }

    @Override
    public CompletionStage<Set<TrustAnchor>> find(byte[] attestationCertificateKeyIdentifier) {
        return metadataBLOBBasedMetadataStatementReactiveRepository.find(attestationCertificateKeyIdentifier).thenApply(metadataStatements -> metadataStatements.stream()
                .flatMap(item -> item.getAttestationRootCertificates().stream())
                .map(item -> new TrustAnchor(item, null))
                .collect(Collectors.toSet()));
    }

    public boolean isNotFidoCertifiedAllowed() {
        return metadataBLOBBasedMetadataStatementReactiveRepository.isNotFidoCertifiedAllowed();
    }

    public void setNotFidoCertifiedAllowed(boolean notFidoCertifiedAllowed) {
        metadataBLOBBasedMetadataStatementReactiveRepository.setNotFidoCertifiedAllowed(notFidoCertifiedAllowed);
    }

    public boolean isSelfAssertionSubmittedAllowed() {
        return metadataBLOBBasedMetadataStatementReactiveRepository.isSelfAssertionSubmittedAllowed();
    }

    public void setSelfAssertionSubmittedAllowed(boolean selfAssertionSubmittedAllowed) {
        metadataBLOBBasedMetadataStatementReactiveRepository.setSelfAssertionSubmittedAllowed(selfAssertionSubmittedAllowed);
    }

}
