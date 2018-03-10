package net.sharplab.springframework.security.webauthn;

import net.sharplab.springframework.security.webauthn.context.WebAuthnAuthenticationContext;
import net.sharplab.springframework.security.webauthn.context.provider.WebAuthnAuthenticationContextProvider;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Spy;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

import java.net.MalformedURLException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Test for WebAuthnProcessingFilter
 */
public class WebAuthnProcessingFilterTest {

    @Rule
    public MockitoRule mockito = MockitoJUnit.rule();

    private WebAuthnAuthenticationContextProvider webAuthnAuthenticationContextProvider;
    private AuthenticationManager authenticationManager;
    private MockHttpServletRequest mockHttpServletRequest;
    private MockHttpServletResponse mockHttpServletResponse;

    @Spy
    private WebAuthnProcessingFilter target;

    private ArgumentCaptor<Authentication> captor = ArgumentCaptor.forClass(Authentication.class);

    @Before
    public void setup(){
        webAuthnAuthenticationContextProvider = mock(WebAuthnAuthenticationContextProvider.class);
        authenticationManager = mock(AuthenticationManager.class);
        mockHttpServletRequest = new MockHttpServletRequest();
        mockHttpServletResponse = new MockHttpServletResponse();

        target.setAuthenticationManager(authenticationManager);
        target.setWebAuthnAuthenticationContextProvider(webAuthnAuthenticationContextProvider);
    }

    @Test
    public void attemptAuthentication_test_with_username_password(){

        mockHttpServletRequest.setMethod("POST");
        mockHttpServletRequest.setParameter("username", "username");
        mockHttpServletRequest.setParameter("password", "password");

        when(authenticationManager.authenticate(captor.capture())).thenReturn(null);
        target.attemptAuthentication(mockHttpServletRequest, mockHttpServletResponse);

        FirstOfMultiFactorAuthenticationToken authenticationToken = (FirstOfMultiFactorAuthenticationToken) captor.getValue();
        assertThat(authenticationToken.getPrincipal()).isEqualTo("username");
        assertThat(authenticationToken.getCredentials()).isEqualTo("password");

    }

    @Test
    public void attemptAuthentication_test_with_credential() {

        String credentialId = "AAhdofeLeQWG6Y6gwwytZKNCDFB1WaIgqDsOwVYR5UavKQhAti4ic9_Dz-_CQEPpN0To6hiDRSCvmFHXaG6HK5yvvhm4DJRVJXzSvZiq5NefbXSYIr2uUaKbsoBe1lulhNdL9dRt6Dkkp38uq02YIR5CDaoxD-HQgMsS667aWlhHVKE884Sq0d1VVgGTDb1ds-Py_H7CDqk9SDErb8-XtQ9L";
        String clientData = "eyJjaGFsbGVuZ2UiOiJGT3JHWklmSFJfeURaSklydTVPdXBBIiwiaGFzaEFsZyI6IlMyNTYiLCJvcmlnaW4iOiJsb2NhbGhvc3QifQ";
        String authenticatorData = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABaQ";
        String signature = "MEUCIGBYMUVg2KkMG7V7UEsGxUeKVaO8x587JyVoZkk6FmsgAiEA5XRKxlYe2Vpwn-JYEJhcEVJ3-0nYFG-JfheOk4rA3dc";
        Authentication currentAuthentication = new AnonymousAuthenticationToken("dummyKey", "anonymous", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));


        //Given
        mockHttpServletRequest.setMethod("POST");
        mockHttpServletRequest.setServerName("example.com");
        mockHttpServletRequest.setParameter("credentialId", credentialId);
        mockHttpServletRequest.setParameter("clientData", clientData);
        mockHttpServletRequest.setParameter("authenticatorData", authenticatorData);
        mockHttpServletRequest.setParameter("signature", signature);

        when(authenticationManager.authenticate(captor.capture())).thenReturn(null);
        when(webAuthnAuthenticationContextProvider.provide(any(), any(), anyString(), anyString(), anyString(), anyString(), any())).thenReturn(mock(WebAuthnAuthenticationContext.class));

        when(target.getCurrentAuthentication()).thenReturn(currentAuthentication);

        //When
        target.attemptAuthentication(mockHttpServletRequest, mockHttpServletResponse);

        //Then
        WebAuthnAssertionAuthenticationToken authenticationToken = (WebAuthnAssertionAuthenticationToken) captor.getValue();
        verify(webAuthnAuthenticationContextProvider).provide(mockHttpServletRequest, mockHttpServletResponse, credentialId, clientData, authenticatorData, signature, currentAuthentication);
        assertThat(authenticationToken.getPrincipal()).isNull();
        assertThat(authenticationToken.getCredentials()).isInstanceOf(WebAuthnAuthenticationContext.class);

    }

    @Test
    public void attemptAuthentication_test_with_get_method() {

        String credentialId = "AAhdofeLeQWG6Y6gwwytZKNCDFB1WaIgqDsOwVYR5UavKQhAti4ic9_Dz-_CQEPpN0To6hiDRSCvmFHXaG6HK5yvvhm4DJRVJXzSvZiq5NefbXSYIr2uUaKbsoBe1lulhNdL9dRt6Dkkp38uq02YIR5CDaoxD-HQgMsS667aWlhHVKE884Sq0d1VVgGTDb1ds-Py_H7CDqk9SDErb8-XtQ9L";
        String clientData = "eyJjaGFsbGVuZ2UiOiJGT3JHWklmSFJfeURaSklydTVPdXBBIiwiaGFzaEFsZyI6IlMyNTYiLCJvcmlnaW4iOiJsb2NhbGhvc3QifQ";
        String authenticatorData = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABaQ";
        String signature = "MEUCIGBYMUVg2KkMG7V7UEsGxUeKVaO8x587JyVoZkk6FmsgAiEA5XRKxlYe2Vpwn-JYEJhcEVJ3-0nYFG-JfheOk4rA3dc";
        Authentication currentAuthentication = new AnonymousAuthenticationToken("dummyKey", "anonymous", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

        //Given
        target.setPostOnly(false);
        mockHttpServletRequest.setMethod("GET");
        mockHttpServletRequest.setServerName("example.com");
        mockHttpServletRequest.setParameter("credentialId", credentialId);
        mockHttpServletRequest.setParameter("clientData", clientData);
        mockHttpServletRequest.setParameter("authenticatorData", authenticatorData);
        mockHttpServletRequest.setParameter("signature", signature);

        when(authenticationManager.authenticate(captor.capture())).thenReturn(null);
        when(webAuthnAuthenticationContextProvider.provide(any(), any(), anyString(), anyString(), anyString(), anyString(), any())).thenReturn(mock(WebAuthnAuthenticationContext.class));

        when(target.getCurrentAuthentication()).thenReturn(currentAuthentication);

        //When
        target.attemptAuthentication(mockHttpServletRequest, mockHttpServletResponse);

        //Then
        WebAuthnAssertionAuthenticationToken authenticationToken = (WebAuthnAssertionAuthenticationToken) captor.getValue();
        verify(webAuthnAuthenticationContextProvider).provide(mockHttpServletRequest, mockHttpServletResponse, credentialId, clientData, authenticatorData, signature, currentAuthentication);
        assertThat(authenticationToken.getPrincipal()).isNull();
        assertThat(authenticationToken.getCredentials()).isInstanceOf(WebAuthnAuthenticationContext.class);

    }


    @Test
    public void attemptAuthentication_test_with_customized_parameter() {

        String usernameParameter = "param_username";
        String passwordParameter = "param_password";
        String credentialIdParameter = "param_credentialId";
        String clientDataParameter = "param_clientData";
        String authenticatorDataParameter = "param_authenticatorData";
        String signatureParameter = "param_signature";

        String credentialId = "AAhdofeLeQWG6Y6gwwytZKNCDFB1WaIgqDsOwVYR5UavKQhAti4ic9_Dz-_CQEPpN0To6hiDRSCvmFHXaG6HK5yvvhm4DJRVJXzSvZiq5NefbXSYIr2uUaKbsoBe1lulhNdL9dRt6Dkkp38uq02YIR5CDaoxD-HQgMsS667aWlhHVKE884Sq0d1VVgGTDb1ds-Py_H7CDqk9SDErb8-XtQ9L";
        String clientData = "eyJjaGFsbGVuZ2UiOiJGT3JHWklmSFJfeURaSklydTVPdXBBIiwiaGFzaEFsZyI6IlMyNTYiLCJvcmlnaW4iOiJsb2NhbGhvc3QifQ";
        String authenticatorData = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABaQ";
        String signature = "MEUCIGBYMUVg2KkMG7V7UEsGxUeKVaO8x587JyVoZkk6FmsgAiEA5XRKxlYe2Vpwn-JYEJhcEVJ3-0nYFG-JfheOk4rA3dc";
        Authentication currentAuthentication = new AnonymousAuthenticationToken("dummyKey", "anonymous", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));


        //Given
        target.setUsernameParameter(usernameParameter);
        target.setPasswordParameter(passwordParameter);
        target.setCredentialIdParameter(credentialIdParameter);
        target.setClientDataParameter(clientDataParameter);
        target.setAuthenticatorDataParameter(authenticatorDataParameter);
        target.setSignatureParameter(signatureParameter);

        mockHttpServletRequest.setMethod("POST");
        mockHttpServletRequest.setServerName("example.com");
        mockHttpServletRequest.setParameter(credentialIdParameter, credentialId);
        mockHttpServletRequest.setParameter(clientDataParameter, clientData);
        mockHttpServletRequest.setParameter(authenticatorDataParameter, authenticatorData);
        mockHttpServletRequest.setParameter(signatureParameter, signature);

        when(authenticationManager.authenticate(captor.capture())).thenReturn(null);
        when(webAuthnAuthenticationContextProvider.provide(any(), any(), anyString(), anyString(), anyString(), anyString(), any())).thenReturn(mock(WebAuthnAuthenticationContext.class));

        when(target.getCurrentAuthentication()).thenReturn(currentAuthentication);

        //When
        target.attemptAuthentication(mockHttpServletRequest, mockHttpServletResponse);

        //Then
        assertThat(target.getUsernameParameter()).isEqualTo(usernameParameter);
        assertThat(target.getPasswordParameter()).isEqualTo(passwordParameter);
        assertThat(target.getCredentialIdParameter()).isEqualTo(credentialIdParameter);
        assertThat(target.getClientDataParameter()).isEqualTo(clientDataParameter);
        assertThat(target.getAuthenticatorDataParameter()).isEqualTo(authenticatorDataParameter);
        assertThat(target.getSignatureParameter()).isEqualTo(signatureParameter);


        WebAuthnAssertionAuthenticationToken authenticationToken = (WebAuthnAssertionAuthenticationToken) captor.getValue();
        verify(webAuthnAuthenticationContextProvider).provide(mockHttpServletRequest, mockHttpServletResponse, credentialId, clientData, authenticatorData, signature, currentAuthentication);
        assertThat(authenticationToken.getPrincipal()).isNull();
        assertThat(authenticationToken.getCredentials()).isInstanceOf(WebAuthnAuthenticationContext.class);

    }


    @Test(expected = AuthenticationServiceException.class)
    public void attemptAuthentication_test_with_wrong_port() {

        //Given
        mockHttpServletRequest.setMethod("GET");
        when(authenticationManager.authenticate(captor.capture())).thenReturn(null);

        //When
        target.attemptAuthentication(mockHttpServletRequest, mockHttpServletResponse);
    }



}
