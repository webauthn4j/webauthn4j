package com.webauthn4j.metadata;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.data.statement.MetadataStatement;
import com.webauthn4j.util.HexUtil;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.Random;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DefaultMetadataStatementRepositoryTest {

    @Test
    void find_by_aaguid_test(){
        AAGUID aaguid = new AAGUID(UUID.randomUUID());
        MetadataStatement metadataStatementA = mock(MetadataStatement.class);
        MetadataStatement metadataStatementB = mock(MetadataStatement.class);
        when(metadataStatementA.getAaguid()).thenReturn(aaguid);
        when(metadataStatementB.getAaguid()).thenReturn(AAGUID.ZERO);
        MetadataStatementsProvider mock = mock(MetadataStatementsProvider.class);
        when(mock.provide()).thenReturn(Arrays.asList(metadataStatementA,metadataStatementB));
        DefaultMetadataStatementRepository target = new DefaultMetadataStatementRepository(mock);
        assertThat(target.find(aaguid)).containsExactly(metadataStatementA);
    }

    @Test
    void find_by_attestationCertificateKeyIdentifier_test(){
        byte[] attestationCertificateKeyIdentifier = new byte[32];
        byte[] anotherAttestationCertificateKeyIdentifier = new byte[32];
        Random random = new Random();
        random.nextBytes(attestationCertificateKeyIdentifier);
        random.nextBytes(anotherAttestationCertificateKeyIdentifier);
        MetadataStatement metadataStatementA = mock(MetadataStatement.class);
        MetadataStatement metadataStatementB = mock(MetadataStatement.class);
        when(metadataStatementA.getAttestationCertificateKeyIdentifiers()).thenReturn(Collections.singletonList(HexUtil.encodeToString(attestationCertificateKeyIdentifier)));
        when(metadataStatementB.getAttestationCertificateKeyIdentifiers()).thenReturn(Collections.singletonList(HexUtil.encodeToString(anotherAttestationCertificateKeyIdentifier)));
        MetadataStatementsProvider mock = mock(MetadataStatementsProvider.class);
        when(mock.provide()).thenReturn(Arrays.asList(metadataStatementA,metadataStatementB));
        DefaultMetadataStatementRepository target = new DefaultMetadataStatementRepository(mock);
        assertThat(target.find(attestationCertificateKeyIdentifier)).containsExactly(metadataStatementA);
    }

}