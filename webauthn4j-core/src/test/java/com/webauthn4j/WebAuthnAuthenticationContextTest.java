package com.webauthn4j;

import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.server.ServerProperty;
import org.junit.Test;

import static com.webauthn4j.client.CollectedClientData.TYPE_WEBAUTHN_GET;
import static com.webauthn4j.test.TestUtil.createAuthenticatorData;
import static com.webauthn4j.test.TestUtil.createClientData;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

public class WebAuthnAuthenticationContextTest {

    @Test
    public void getter_test() {

        byte[] credentialId = new byte[32];
        byte[] collectedClientData = new CollectedClientDataConverter().convertToBytes(createClientData(TYPE_WEBAUTHN_GET));
        byte[] authenticatorData = new AuthenticatorDataConverter().convert(createAuthenticatorData());
        byte[] signature = new byte[]{0x01, 0x23};
        ServerProperty serverProperty = mock(ServerProperty.class);
        WebAuthnAuthenticationContext target = new WebAuthnAuthenticationContext(
                credentialId, collectedClientData, authenticatorData, signature, serverProperty, false);
        assertThat(target.getCredentialId()).isEqualTo(credentialId);
        assertThat(target.getClientDataJSON()).isEqualTo(collectedClientData);
        assertThat(target.getAuthenticatorData()).isEqualTo(authenticatorData);
        assertThat(target.getSignature()).isEqualTo(signature);
        assertThat(target.getServerProperty()).isEqualTo(serverProperty);
        assertThat(target.isUserVerificationRequired()).isFalse();
    }

    @Test
    public void equals_hashCode_test() {
        byte[] credentialId = new byte[32];
        byte[] collectedClientData = new CollectedClientDataConverter().convertToBytes(createClientData(TYPE_WEBAUTHN_GET));
        byte[] authenticatorData = new AuthenticatorDataConverter().convert(createAuthenticatorData());
        byte[] signature = new byte[]{0x01, 0x23};
        ServerProperty serverProperty = mock(ServerProperty.class);
        WebAuthnAuthenticationContext webAuthnAuthenticationContextA = new WebAuthnAuthenticationContext(
                credentialId, collectedClientData, authenticatorData, signature, serverProperty, true);
        WebAuthnAuthenticationContext webAuthnAuthenticationContextB = new WebAuthnAuthenticationContext(
                credentialId, collectedClientData, authenticatorData, signature, serverProperty, true);

        assertThat(webAuthnAuthenticationContextA).isEqualTo(webAuthnAuthenticationContextB);
        assertThat(webAuthnAuthenticationContextA).hasSameHashCodeAs(webAuthnAuthenticationContextB);
    }
}
