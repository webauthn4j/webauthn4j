package com.webauthn4j.spc.data;

import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SPCRegistrationParametersTest {

    private static final ServerProperty SERVER_PROPERTY = ServerProperty.builder()
            .origin(new Origin("https://example.com")).rpId("example.com").challenge(new DefaultChallenge()).build();
    private static final List<PublicKeyCredentialParameters> PUB_KEY_CRED_PARAMS = List.of(
            new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256));

    @Test
    void constructor_with_all_params() {
        var params = new SPCRegistrationParameters(SERVER_PROPERTY, PUB_KEY_CRED_PARAMS, false, false);
        assertThat(params.getServerProperty()).isEqualTo(SERVER_PROPERTY);
        assertThat(params.getPubKeyCredParams()).isEqualTo(PUB_KEY_CRED_PARAMS);
        assertThat(params.isUserVerificationRequired()).isFalse();
        assertThat(params.isUserPresenceRequired()).isFalse();
    }

    @Test
    void constructor_with_defaults() {
        var params = new SPCRegistrationParameters(SERVER_PROPERTY, PUB_KEY_CRED_PARAMS);
        assertThat(params.getServerProperty()).isEqualTo(SERVER_PROPERTY);
        assertThat(params.isUserVerificationRequired()).isTrue();
        assertThat(params.isUserPresenceRequired()).isTrue();
    }
}
