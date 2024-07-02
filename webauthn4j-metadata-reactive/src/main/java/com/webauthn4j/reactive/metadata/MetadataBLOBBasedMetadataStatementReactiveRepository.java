package com.webauthn4j.reactive.metadata;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.data.MetadataBLOBPayloadEntry;
import com.webauthn4j.metadata.data.statement.MetadataStatement;
import com.webauthn4j.metadata.util.internal.MetadataBLOBUtil;
import com.webauthn4j.metadata.util.internal.MetadataStatementUtil;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.webauthn4j.metadata.MetadataBLOBBasedMetadataStatementRepository.matchAttestationCertificateKeyIdentifier;

public class MetadataBLOBBasedMetadataStatementReactiveRepository implements MetadataStatementReactiveRepository{

    private final List<MetadataBLOBReactiveProvider> metadataBLOBReactiveProviders;

    private boolean notFidoCertifiedAllowed = false;
    private boolean selfAssertionSubmittedAllowed = false;

    public MetadataBLOBBasedMetadataStatementReactiveRepository(MetadataBLOBReactiveProvider... metadataBLOBReactiveProviders) {
        this.metadataBLOBReactiveProviders = Arrays.asList(metadataBLOBReactiveProviders);
    }

    @Override
    public CompletionStage<Set<MetadataStatement>> find(AAGUID aaguid) {
        return metadataBLOBReactiveProviders.stream()
                .map(provider -> provider.provide().thenApply(metadataBLOB -> metadataBLOB.getPayload().getEntries().stream()))
                .reduce(CompletableFuture.completedFuture(Stream.empty()),
                        (a, b)-> a.thenCombine(b, Stream::concat)
                ).thenApply(entries ->
                        entries
                        .filter(entry -> Objects.equals(entry.getAaguid(), aaguid))
                        .filter(entry -> MetadataBLOBUtil.checkMetadataBLOBPayloadEntry(entry, notFidoCertifiedAllowed, selfAssertionSubmittedAllowed))
                        .map(MetadataBLOBPayloadEntry::getMetadataStatement)
                        .filter(MetadataStatementUtil::checkSurrogateMetadataStatementAttestationRootCertificate)
                        .collect(Collectors.toSet())
                );
    }

    @Override
    public CompletionStage<Set<MetadataStatement>> find(byte[] attestationCertificateKeyIdentifier) {
        return metadataBLOBReactiveProviders.stream()
                .map(provider -> provider.provide().thenApply(metadataBLOB -> metadataBLOB.getPayload().getEntries().stream()))
                .reduce(CompletableFuture.completedFuture(Stream.empty()), (a, b)-> a.thenCombine(b, Stream::concat))
                .thenApply(entries -> entries
                        .filter(entry -> matchAttestationCertificateKeyIdentifier(entry, attestationCertificateKeyIdentifier))
                        .map(MetadataBLOBPayloadEntry::getMetadataStatement)
                        .filter(MetadataStatementUtil::checkSurrogateMetadataStatementAttestationRootCertificate)
                        .collect(Collectors.toSet()));
    }

    public boolean isNotFidoCertifiedAllowed() {
        return notFidoCertifiedAllowed;
    }

    public void setNotFidoCertifiedAllowed(boolean notFidoCertifiedAllowed) {
        this.notFidoCertifiedAllowed = notFidoCertifiedAllowed;
    }

    public boolean isSelfAssertionSubmittedAllowed() {
        return selfAssertionSubmittedAllowed;
    }

    public void setSelfAssertionSubmittedAllowed(boolean selfAssertionSubmittedAllowed) {
        this.selfAssertionSubmittedAllowed = selfAssertionSubmittedAllowed;
    }



}
