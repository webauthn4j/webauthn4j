package net.sharplab.springframework.security.webauthn;

import net.sharplab.springframework.security.webauthn.context.WebAuthnAuthenticationContext;
import net.sharplab.springframework.security.webauthn.context.provider.WebAuthnAuthenticationContextProvider;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.FirstOfMultiFactorAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;


/**
 * WebAuthnProcessingFilter
 */
public class WebAuthnProcessingFilter extends UsernamePasswordAuthenticationFilter {

    // ~ Static fields/initializers
    // =====================================================================================
    public static final String SPRING_SECURITY_FORM_CREDENTIAL_ID_KEY = "credentialId";
    public static final String SPRING_SECURITY_FORM_CLIENTDATA_KEY = "clientData";
    public static final String SPRING_SECURITY_FORM_AUTHENTICATOR_DATA_KEY = "authenticatorData";
    public static final String SPRING_SECURITY_FORM_SIGNATURE_KEY = "signature";

    //~ Instance fields
    // ================================================================================================
    private List<GrantedAuthority> authorities;

    private String credentialIdParameter = SPRING_SECURITY_FORM_CREDENTIAL_ID_KEY;
    private String clientDataParameter = SPRING_SECURITY_FORM_CLIENTDATA_KEY;
    private String authenticatorDataParameter = SPRING_SECURITY_FORM_AUTHENTICATOR_DATA_KEY;
    private String signatureParameter = SPRING_SECURITY_FORM_SIGNATURE_KEY;




    private WebAuthnAuthenticationContextProvider webAuthnAuthenticationContextProvider;

    private boolean postOnly = true;

    public WebAuthnProcessingFilter() {
        this(AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
    }

    public WebAuthnProcessingFilter(List<GrantedAuthority> authorities){
        super();
        Assert.notNull(authorities, "Anonymous authorities must be set");
        this.authorities = authorities;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        if (postOnly && !HttpMethod.POST.matches(request.getMethod())) {
            throw new AuthenticationServiceException(
                    "Authentication method not supported: " + request.getMethod());
        }

        String username = obtainUsername(request);
        String password = obtainPassword(request);

        String credentialId = obtainCredentialId(request);
        String clientData = obtainClientData(request);
        String authenticatorData = obtainAuthenticatorData(request);
        String signature = obtainSignatureData(request);

        AbstractAuthenticationToken authRequest;
        if (StringUtils.isEmpty(credentialId)) {
            authRequest = new FirstOfMultiFactorAuthenticationToken(username, password, authorities);
        }
        else {
            Authentication currentAuthentication = getCurrentAuthentication();

            WebAuthnAuthenticationContext webAuthnAuthenticationContext =
                    getWebAuthnAuthenticationContextProvider().provide(request, response, credentialId, clientData, authenticatorData, signature, currentAuthentication);

            authRequest = new WebAuthnAssertionAuthenticationToken(webAuthnAuthenticationContext);
        }

        // Allow subclasses to set the "details" property
        setDetails(request, authRequest);

        return this.getAuthenticationManager().authenticate(authRequest);
    }

    Authentication getCurrentAuthentication(){
        return SecurityContextHolder.getContext().getAuthentication();
    }

    private String obtainClientData(HttpServletRequest request) {
        return request.getParameter(clientDataParameter);
    }

    private String obtainCredentialId(HttpServletRequest request) {
        return request.getParameter(credentialIdParameter);
    }

    private String obtainAuthenticatorData(HttpServletRequest request) {
        return request.getParameter(authenticatorDataParameter);
    }

    private String obtainSignatureData(HttpServletRequest request) {
        return request.getParameter(signatureParameter);
    }

    private void setDetails(HttpServletRequest request,
                            AbstractAuthenticationToken authRequest) {
        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
    }

    /**
     * Defines whether only HTTP POST requests will be allowed by this filter. If set to
     * true, and an authentication request is received which is not a POST request, an
     * exception will be raised immediately and authentication will not be attempted. The
     * <tt>unsuccessfulAuthentication()</tt> method will be called as if handling a failed
     * authentication.
     * <p>
     * Defaults to <tt>true</tt> but may be overridden by subclasses.
     *
     * @param postOnly Flag to restrict HTTP method to POST.
     */
    public void setPostOnly(boolean postOnly) {
        this.postOnly = postOnly;
    }

    public String getCredentialIdParameter() {
        return credentialIdParameter;
    }

    public void setCredentialIdParameter(String credentialIdParameter) {
        this.credentialIdParameter = credentialIdParameter;
    }

    public String getClientDataParameter() {
        return clientDataParameter;
    }

    public void setClientDataParameter(String clientDataParameter) {
        this.clientDataParameter = clientDataParameter;
    }

    public String getAuthenticatorDataParameter() {
        return authenticatorDataParameter;
    }

    public void setAuthenticatorDataParameter(String authenticatorDataParameter) {
        this.authenticatorDataParameter = authenticatorDataParameter;
    }

    public String getSignatureParameter() {
        return signatureParameter;
    }

    public void setSignatureParameter(String signatureParameter) {
        this.signatureParameter = signatureParameter;
    }

    protected WebAuthnAuthenticationContextProvider getWebAuthnAuthenticationContextProvider() {
        return webAuthnAuthenticationContextProvider;
    }

    public void setWebAuthnAuthenticationContextProvider(WebAuthnAuthenticationContextProvider webAuthnAuthenticationContextProvider) {
        this.webAuthnAuthenticationContextProvider = webAuthnAuthenticationContextProvider;
    }

}
