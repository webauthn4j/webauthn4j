package com.webauthn4j.async.metadata.anchor;

import com.webauthn4j.async.anchor.TrustAnchorAsyncRepository;
import com.webauthn4j.async.metadata.LocalFilesMetadataStatementsAsyncProvider;
import com.webauthn4j.async.metadata.MetadataStatementsAsyncProvider;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.util.HexUtil;

import java.nio.file.Path;
import java.security.cert.TrustAnchor;
import java.util.Arrays;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletionStage;
import java.util.stream.Collectors;

public class MetadataStatementsBasedTrustAnchorAsyncRepository implements TrustAnchorAsyncRepository {

    private final MetadataStatementsAsyncProvider metadataStatementsAsyncProvider;

    public MetadataStatementsBasedTrustAnchorAsyncRepository(MetadataStatementsAsyncProvider metadataStatementsAsyncProvider) {
        this.metadataStatementsAsyncProvider = metadataStatementsAsyncProvider;
    }

    public MetadataStatementsBasedTrustAnchorAsyncRepository(ObjectConverter objectConverter, Path... paths) {
        this(new LocalFilesMetadataStatementsAsyncProvider(objectConverter, paths));
    }

    @Override
    public CompletionStage<Set<TrustAnchor>> find(AAGUID aaguid) {
        return metadataStatementsAsyncProvider.provide().thenApply( metadataStatements -> metadataStatements.stream()
                .filter(metadataStatement -> Objects.equals(aaguid, metadataStatement.getAaguid()))
                .flatMap(metadataStatement -> metadataStatement.getAttestationRootCertificates().stream())
                .map(item -> new TrustAnchor(item, null))
                .collect(Collectors.toSet()));
    }

    @Override
    public CompletionStage<Set<TrustAnchor>> find(byte[] attestationCertificateKeyIdentifier) {
        return metadataStatementsAsyncProvider.provide().thenApply( metadataStatements -> metadataStatements.stream()
                .filter(metadataStatement -> metadataStatement.getAttestationCertificateKeyIdentifiers() != null && metadataStatement.getAttestationCertificateKeyIdentifiers().stream().anyMatch(identifier -> Arrays.equals(HexUtil.decode(identifier), attestationCertificateKeyIdentifier)))
                .map(metadataStatement -> new TrustAnchor(metadataStatement.getAttestationRootCertificates().get(0), null))
                .collect(Collectors.toSet()));
    }
}
