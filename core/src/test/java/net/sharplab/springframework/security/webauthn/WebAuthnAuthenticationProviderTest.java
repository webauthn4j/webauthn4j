/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.sharplab.springframework.security.webauthn;

import net.sharplab.springframework.security.webauthn.authenticator.WebAuthnAuthenticator;
import net.sharplab.springframework.security.webauthn.authenticator.WebAuthnAuthenticatorImpl;
import net.sharplab.springframework.security.webauthn.authenticator.WebAuthnAuthenticatorService;
import net.sharplab.springframework.security.webauthn.context.WebAuthnAuthenticationContext;
import net.sharplab.springframework.security.webauthn.exception.CredentialIdNotFoundException;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsImpl;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test for WebAuthnAuthenticationProvider
 */
public class WebAuthnAuthenticationProviderTest {

    @Rule
    public MockitoRule mockito = MockitoJUnit.rule();

    @Mock
    WebAuthnAuthenticatorService webAuthnAuthenticatorService;

    @InjectMocks
    WebAuthnAuthenticationProvider webAuthnAuthenticationProvider;


    /**
     * Verifies that unsupported Authentication object will be rejected.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testInvalidAuthenticationObject() {
        Authentication token = new UsernamePasswordAuthenticationToken("username", "password");
        webAuthnAuthenticationProvider.authenticate(token);
    }

    /**
     * Verifies that authentication process passes successfully if input is correct.
     */
    @Test
    @Ignore
    public void testAuthenticate() {
        //Given
        byte[] credentialId = new byte[0];
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");
        WebAuthnUserDetailsImpl user = new WebAuthnUserDetailsImpl(
                "username",
                "$2a$10$P2/aZvvln5dWs9T96ycx0eNFS1EwdiElzRjMObg8j0rTDISHMEdoq",
                Collections.emptyList(),
                Collections.singletonList(grantedAuthority));
        WebAuthnAuthenticator authenticator = new WebAuthnAuthenticatorImpl("authenticator", user, null, null);

        when(webAuthnAuthenticatorService.loadWebAuthnAuthenticatorByCredentialId(credentialId))
                .thenReturn(authenticator);

        //When
        WebAuthnAuthenticationContext credential = mock(WebAuthnAuthenticationContext.class);
        Authentication token = new WebAuthnAssertionAuthenticationToken(credential);
        Authentication authenticatedToken = webAuthnAuthenticationProvider.authenticate(token);

        assertThat(authenticatedToken.getPrincipal()).isInstanceOf(WebAuthnUserDetailsImpl.class);
        assertThat(authenticatedToken.getCredentials()).isEqualTo(credential);
        assertThat(authenticatedToken.getAuthorities().toArray()).containsExactly(grantedAuthority);
    }


    @Test
    public void retrieveWebAuthnAuthenticator_test() {
        byte[] credentialId = new byte[0];
        WebAuthnAssertionAuthenticationToken authenticationToken = null;
        WebAuthnAuthenticator expectedAuthenticator = mock(WebAuthnAuthenticator.class);

        //Given
        when(webAuthnAuthenticatorService.loadWebAuthnAuthenticatorByCredentialId(credentialId)).thenReturn(expectedAuthenticator);

        //When
        WebAuthnAuthenticator authenticator = webAuthnAuthenticationProvider.retrieveWebAuthnAuthenticator(credentialId, authenticationToken);

        //Then
        assertThat(authenticator).isEqualTo(expectedAuthenticator);

    }

    @Test(expected = BadCredentialsException.class)
    public void retrieveWebAuthnAuthenticator_test_with_CredentialIdNotFoundException() {
        byte[] credentialId = new byte[0];
        WebAuthnAssertionAuthenticationToken authenticationToken = null;

        //Given
        when(webAuthnAuthenticatorService.loadWebAuthnAuthenticatorByCredentialId(credentialId)).thenThrow(CredentialIdNotFoundException.class);

        //When
        webAuthnAuthenticationProvider.retrieveWebAuthnAuthenticator(credentialId, authenticationToken);
    }

    @Test(expected = CredentialIdNotFoundException.class)
    public void retrieveWebAuthnAuthenticator_test_with_CredentialIdNotFoundException_and_hideCredentialIdNotFoundExceptions_option_false() {
        byte[] credentialId = new byte[0];
        WebAuthnAssertionAuthenticationToken authenticationToken = null;

        //Given
        when(webAuthnAuthenticatorService.loadWebAuthnAuthenticatorByCredentialId(credentialId)).thenThrow(CredentialIdNotFoundException.class);

        //When
        webAuthnAuthenticationProvider.setHideCredentialIdNotFoundExceptions(false);
        webAuthnAuthenticationProvider.retrieveWebAuthnAuthenticator(credentialId, authenticationToken);
    }

    @Test(expected = InternalAuthenticationServiceException.class)
    public void retrieveWebAuthnAuthenticator_test_with_RuntimeException_from_webAuthnAuthenticatorService() {
        byte[] credentialId = new byte[0];
        WebAuthnAssertionAuthenticationToken authenticationToken = null;

        //Given
        when(webAuthnAuthenticatorService.loadWebAuthnAuthenticatorByCredentialId(credentialId)).thenThrow(RuntimeException.class);

        //When
        webAuthnAuthenticationProvider.setHideCredentialIdNotFoundExceptions(false);
        webAuthnAuthenticationProvider.retrieveWebAuthnAuthenticator(credentialId, authenticationToken);
    }

    @Test(expected = InternalAuthenticationServiceException.class)
    public void retrieveWebAuthnAuthenticator_test_with_null_from_webAuthnAuthenticatorService() {
        byte[] credentialId = new byte[0];
        WebAuthnAssertionAuthenticationToken authenticationToken = null;

        //Given
        when(webAuthnAuthenticatorService.loadWebAuthnAuthenticatorByCredentialId(credentialId)).thenReturn(null);

        //When
        webAuthnAuthenticationProvider.setHideCredentialIdNotFoundExceptions(false);
        webAuthnAuthenticationProvider.retrieveWebAuthnAuthenticator(credentialId, authenticationToken);
    }

}
