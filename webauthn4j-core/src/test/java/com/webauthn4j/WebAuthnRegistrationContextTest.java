package com.webauthn4j;

import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.server.ServerProperty;
import org.junit.Test;

import static com.webauthn4j.client.CollectedClientData.TYPE_WEBAUTHN_GET;
import static com.webauthn4j.test.TestUtil.createAttestationObjectWithFIDOU2FAttestationStatement;
import static com.webauthn4j.test.TestUtil.createClientData;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

public class WebAuthnRegistrationContextTest {

    @Test
    public void test() {
        byte[] collectedClientData = new CollectedClientDataConverter().convertToBytes(createClientData(TYPE_WEBAUTHN_GET));
        byte[] authenticatorData = new AttestationObjectConverter().convertToBytes(createAttestationObjectWithFIDOU2FAttestationStatement());

        ServerProperty serverProperty = mock(ServerProperty.class);

        WebAuthnRegistrationContext webAuthnRegistrationContextA = new WebAuthnRegistrationContext(collectedClientData, authenticatorData, serverProperty, false, expectedExtensions);
        WebAuthnRegistrationContext webAuthnRegistrationContextB = new WebAuthnRegistrationContext(collectedClientData, authenticatorData, serverProperty, false, expectedExtensions);

        assertThat(webAuthnRegistrationContextA).isEqualTo(webAuthnRegistrationContextB);
        assertThat(webAuthnRegistrationContextA).hasSameHashCodeAs(webAuthnRegistrationContextB);
    }

}
