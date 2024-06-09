package com.webauthn4j.async.metadata;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.data.statement.MetadataStatement;

import java.util.Set;
import java.util.concurrent.CompletionStage;

public interface MetadataStatementAsyncRepository {

    CompletionStage<Set<MetadataStatement>> find(AAGUID aaguid);

    CompletionStage<Set<MetadataStatement>> find(byte[] attestationCertificateKeyIdentifier);
}
