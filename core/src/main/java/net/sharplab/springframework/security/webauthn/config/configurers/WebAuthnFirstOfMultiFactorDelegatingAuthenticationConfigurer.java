package net.sharplab.springframework.security.webauthn.config.configurers;

import net.sharplab.springframework.security.webauthn.WebAuthnFirstOfMultiFactorDelegatingAuthenticationProvider;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 *
 * @param <B> the type of the {@link SecurityBuilder}
 * @param <C> the type of {@link WebAuthnFirstOfMultiFactorDelegatingAuthenticationConfigurer} this is
 * @param <U> The type of {@link UserDetailsService} that is being used
 */
public class WebAuthnFirstOfMultiFactorDelegatingAuthenticationConfigurer<B extends ProviderManagerBuilder<B>, C extends WebAuthnFirstOfMultiFactorDelegatingAuthenticationConfigurer<B, C, U>, U extends UserDetailsService>
        extends SecurityConfigurerAdapter<AuthenticationManager, B> {

    private AbstractUserDetailsAuthenticationProvider authenticationProvider;

    public WebAuthnFirstOfMultiFactorDelegatingAuthenticationConfigurer(AbstractUserDetailsAuthenticationProvider authenticationProvider){
        this.authenticationProvider = authenticationProvider;
    }

    @Override
    public void configure(B builder) {
        WebAuthnFirstOfMultiFactorDelegatingAuthenticationProvider delegatingAuthenticationProvider = new WebAuthnFirstOfMultiFactorDelegatingAuthenticationProvider(authenticationProvider);
        delegatingAuthenticationProvider = postProcess(delegatingAuthenticationProvider);
        builder.authenticationProvider(delegatingAuthenticationProvider);
    }
}
