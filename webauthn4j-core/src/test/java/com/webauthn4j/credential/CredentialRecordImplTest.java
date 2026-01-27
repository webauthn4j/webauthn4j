package com.webauthn4j.credential;

import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.test.TestDataUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

class CredentialRecordImplTest {

    private AttestationObject attestationObject;
    private CollectedClientData clientData;
    private AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions;
    private Set<AuthenticatorTransport> transports;

    @BeforeEach
    void setUp() {
        attestationObject = TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        clientData = TestDataUtil.createClientData(ClientDataType.WEBAUTHN_CREATE);
        clientExtensions = new AuthenticationExtensionsClientOutputs<>();
        transports = new HashSet<>();
    }

    @Test
    void shouldCreateCredentialRecordWithValidParameters() {
        // Given

        // When
        CredentialRecord credentialRecord = new CredentialRecordImpl(
                attestationObject,
                clientData,
                clientExtensions,
                transports
        );

        // Then
        assertThat(credentialRecord.getClientData()).isEqualTo(clientData);
        assertThat(credentialRecord.getClientExtensions()).isEqualTo(clientExtensions);
        assertThat(credentialRecord.getTransports()).isEqualTo(transports);
    }

    @Test
    void shouldCreateCredentialRecordWithEmptyTransports() {
        // Given
        Set<AuthenticatorTransport> emptyTransports = new HashSet<>();

        // When
        CredentialRecord credentialRecord = new CredentialRecordImpl(
                attestationObject,
                clientData,
                clientExtensions,
                emptyTransports
        );

        // Then
        assertThat(credentialRecord.getTransports()).isEmpty();
    }

    @Test
    void shouldBeEqualWhenAllPropertiesAreEqual() {
        // Given
        CredentialRecord instanceA = new CredentialRecordImpl(
                attestationObject,
                clientData,
                clientExtensions,
                transports
        );
        CredentialRecord instanceB = new CredentialRecordImpl(
                attestationObject,
                clientData,
                clientExtensions,
                transports
        );

        // When
        // Then
        assertThat(instanceA)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);
    }

    @Test
    void shouldNotBeEqualWhenClientDataDiffers() {
        // Given
        CredentialRecord instanceA = new CredentialRecordImpl(
                attestationObject,
                clientData,
                clientExtensions,
                transports
        );
        CredentialRecord instanceB = new CredentialRecordImpl(
                attestationObject,
                TestDataUtil.createClientData(ClientDataType.WEBAUTHN_GET),
                clientExtensions,
                transports
        );

        // When
        // Then
        assertThat(instanceA).isNotEqualTo(instanceB);
    }

    @Test
    void shouldHandleNullClientExtensions() {
        // Given
        AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> nullExtensions = null;

        // When
        // Then
        assertThatCode(() -> new CredentialRecordImpl(
                attestationObject,
                clientData,
                nullExtensions,
                transports
        )).doesNotThrowAnyException();
    }
}
