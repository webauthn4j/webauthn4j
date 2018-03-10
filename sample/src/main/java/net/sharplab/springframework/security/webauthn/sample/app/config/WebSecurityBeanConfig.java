package net.sharplab.springframework.security.webauthn.sample.app.config;

import net.sharplab.springframework.security.webauthn.WebAuthnAuthenticationProvider;
import net.sharplab.springframework.security.webauthn.anchor.FIDOMetadataServiceTrustAnchorService;
import net.sharplab.springframework.security.webauthn.authenticator.WebAuthnAuthenticatorService;
import net.sharplab.springframework.security.webauthn.client.challenge.ChallengeRepository;
import net.sharplab.springframework.security.webauthn.client.challenge.HttpSessionChallengeRepository;
import net.sharplab.springframework.security.webauthn.context.provider.*;
import net.sharplab.springframework.security.webauthn.context.validator.WebAuthnAuthenticationContextValidator;
import net.sharplab.springframework.security.webauthn.context.validator.WebAuthnRegistrationContextValidator;
import net.sharplab.springframework.security.webauthn.context.validator.assertion.signature.AssertionSignatureValidator;
import net.sharplab.springframework.security.webauthn.context.validator.assertion.signature.FIDOU2FAssertionSignatureValidator;
import net.sharplab.springframework.security.webauthn.context.validator.assertion.signature.WebAuthnAssertionSignatureValidator;
import net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.AttestationStatementTrustworthinessValidator;
import net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.LooseAttestationStatementTrustworthinessValidator;
import net.sharplab.springframework.security.webauthn.metadata.MetadataProvider;
import net.sharplab.springframework.security.webauthn.metadata.MetadataProviderImpl;
import net.sharplab.springframework.security.webauthn.sample.domain.component.AuthenticatorManager;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.DelegatingAccessDeniedHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.security.web.csrf.MissingCsrfTokenException;
import org.springframework.security.web.session.InvalidSessionAccessDeniedHandler;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SimpleRedirectInvalidSessionStrategy;

import java.util.LinkedHashMap;
import java.util.List;

@Configuration
public class WebSecurityBeanConfig {

    @Bean
    public WebAuthnAuthenticationContextProvider webAuthnAuthenticationContextProvider(RelyingPartyProvider relyingPartyProvider){
        return new WebAuthnAuthenticationContextProviderImpl(relyingPartyProvider);
    }

    @Bean
    public WebAuthnAuthenticationContextValidator webAuthnAuthenticationContextValidator(List<AssertionSignatureValidator> assertionSignatureValidators){
        return new WebAuthnAuthenticationContextValidator(assertionSignatureValidators);
    }

    @Bean
    public WebAuthnRegistrationContextProvider webAuthnRegistrationContextProvider(RelyingPartyProvider relyingPartyProvider){
        return new WebAuthnRegistrationContextProviderImpl(relyingPartyProvider);
    }

    @Bean
    public FIDOU2FAssertionSignatureValidator fidou2FAssertionSignatureValidator(){
        return new FIDOU2FAssertionSignatureValidator();
    }

    @Bean
    public RelyingPartyProvider relyingPartyProvider(ChallengeRepository challengeRepository){
        RelyingPartyProvider relyingPartyProvider = new RelyingPartyProviderImpl(challengeRepository);
        return relyingPartyProvider;
    }

    @Bean //TODO:なぜBean化が自前で必要？
    public AuthenticationTrustResolver authenticationTrustResolver(){
        return new AuthenticationTrustResolverImpl();
    }

    @Bean
    public ChallengeRepository challengeRepository(){
        return new HttpSessionChallengeRepository();
    }

    @Bean
    public WebAuthnRegistrationContextValidator webAuthnRegistrationContextValidator(AttestationStatementTrustworthinessValidator attestationStatementTrustworthinessValidator){
        return new WebAuthnRegistrationContextValidator(attestationStatementTrustworthinessValidator);
    }

    @Bean
    public AttestationStatementTrustworthinessValidator attestationStatementTrustworthinessValidator(FIDOMetadataServiceTrustAnchorService fidoMetadataServiceTrustAnchorService){
        return new LooseAttestationStatementTrustworthinessValidator(fidoMetadataServiceTrustAnchorService);
    }

    @Bean
    public WebAuthnAssertionSignatureValidator webAuthnAssertionSignatureVerifier(){
        return new WebAuthnAssertionSignatureValidator();
    }

    @Bean
    public MetadataProvider metadataProvider(WebAuthnUserDetailsService userDetailsService){
        return new MetadataProviderImpl(userDetailsService);
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(PasswordEncoder passwordEncoder, UserDetailsService userDetailsService){
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        return daoAuthenticationProvider;
    }


    @Bean
    public WebAuthnAuthenticationProvider webAuthnAuthenticationProvider(
            AuthenticatorManager authenticatorManager,
            WebAuthnAuthenticatorService webAuthnAuthenticatorService,
            WebAuthnAuthenticationContextValidator authenticationContextValidator){

        WebAuthnAuthenticationProvider webAuthnAuthenticationProvider = new WebAuthnAuthenticationProvider(webAuthnAuthenticatorService, authenticationContextValidator);
        webAuthnAuthenticationProvider.setAuthenticatorService(authenticatorManager);
        return webAuthnAuthenticationProvider;
    }

    @Bean
    public HttpSessionSecurityContextRepository httpSessionSecurityContextRepository(){
        return new HttpSessionSecurityContextRepository();
    }

    @Bean
    public InvalidSessionStrategy invalidSessionStrategy(){
        return new SimpleRedirectInvalidSessionStrategy("/login?expired");
    }

    @Bean
    public InvalidSessionAccessDeniedHandler invalidSessionAccessDeniedHandler(InvalidSessionStrategy invalidSessionStrategy){
        InvalidSessionAccessDeniedHandler accessDeniedHandler = new InvalidSessionAccessDeniedHandler(invalidSessionStrategy);
        return accessDeniedHandler;
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler(){
        LinkedHashMap<Class<? extends AccessDeniedException>, AccessDeniedHandler> errorHandlers = new LinkedHashMap<>();

        // invalid csrf token error handler
        AccessDeniedHandlerImpl invalidCsrfTokenErrorHandler = new AccessDeniedHandlerImpl();
        invalidCsrfTokenErrorHandler.setErrorPage("/error/invalidCsrfTokenError");
        errorHandlers.put(InvalidCsrfTokenException.class, invalidCsrfTokenErrorHandler);

        // invalid csrf token error handler
        AccessDeniedHandlerImpl missingCsrfTokenErrorHandler = new AccessDeniedHandlerImpl();
        missingCsrfTokenErrorHandler.setErrorPage("/error/invalidCsrfTokenError");
        errorHandlers.put(MissingCsrfTokenException.class, missingCsrfTokenErrorHandler);

        // default error handler
        AccessDeniedHandlerImpl defaultErrorHandler = new AccessDeniedHandlerImpl();
        defaultErrorHandler.setErrorPage("/error/accessDeniedError");

        return new DelegatingAccessDeniedHandler(errorHandlers, defaultErrorHandler);
    }

}
