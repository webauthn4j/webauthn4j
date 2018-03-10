package net.sharplab.springframework.security.webauthn;

import net.sharplab.springframework.security.webauthn.context.WebAuthnAuthenticationContext;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Test for WebAuthnAuthenticationToken
 */
public class WebAuthnAuthenticationTokenTest {

    /**
     * Verifies that constructor with 3 args yields authenticated token.
     */
    @Test
    public void webAuthnAuthenticationToken(){
        WebAuthnAuthenticationToken webAuthnAuthenticationToken = new WebAuthnAuthenticationToken(null, null, null);
        assertThat(webAuthnAuthenticationToken.isAuthenticated()).isTrue();
    }

    /**
     * Verifies that getter returns constructor parameters
     */
    @Test
    public void test_methods(){
        WebAuthnAuthenticationContext credential = mock(WebAuthnAuthenticationContext.class);
        WebAuthnAuthenticationToken webAuthnAuthenticationToken = new WebAuthnAuthenticationToken("username", credential, null);

        assertThat(webAuthnAuthenticationToken.getPrincipal()).isEqualTo("username");
        assertThat(webAuthnAuthenticationToken.getCredentials()).isEqualTo(credential);
    }


}
