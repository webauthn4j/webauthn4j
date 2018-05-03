package net.sharplab.springframework.security.webauthn.sample.app.config;

import net.sharplab.springframework.security.webauthn.WebAuthnAuthenticationProvider;
import net.sharplab.springframework.security.webauthn.config.configurers.WebAuthnFirstOfMultiFactorDelegatingAuthenticationConfigurer;
import net.sharplab.springframework.security.webauthn.context.provider.WebAuthnAuthenticationContextProvider;
import net.sharplab.springframework.security.webauthn.metadata.MetadataProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.inject.Named;

import static net.sharplab.springframework.security.webauthn.config.configurers.WebAuthnLoginConfigurer.webAuthnLogin;


/**
 * Security Configuration
 */
@Configuration
@Import(value = WebSecurityBeanConfig.class)
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private static final String ADMIN_ROLE = "ADMIN";

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private InvalidSessionStrategy invalidSessionStrategy;

    @Autowired
    @Named("accessDeniedHandler")
    private AccessDeniedHandler accessDeniedHandler;

    @Autowired
    private WebAuthnAuthenticationContextProvider webAuthnAuthenticationContextProvider;

    @Autowired
    private DaoAuthenticationProvider daoAuthenticationProvider;

    @Autowired
    private HttpSessionSecurityContextRepository httpSessionSecurityContextRepository;

    @Autowired
    private MetadataProvider metadataProvider;


    @Override
    public void configure(AuthenticationManagerBuilder builder) throws Exception {
        builder.apply(new WebAuthnFirstOfMultiFactorDelegatingAuthenticationConfigurer<>(daoAuthenticationProvider));
        builder.authenticationProvider(applicationContext.getBean(WebAuthnAuthenticationProvider.class));
    }

    @Override
    public void configure(WebSecurity web) {
        // ignore static resources
        web.ignoring().antMatchers(
                "/image/**",
                "/css/**",
                "/js/**");
    }

    /**
     * Configure SecurityFilterChain
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // Authorization
        http.authorizeRequests()
                .mvcMatchers("/login").permitAll()
                .mvcMatchers("/signup").permitAll()
                .mvcMatchers("/health/**").permitAll()
                .mvcMatchers("/info/**").permitAll()
                .mvcMatchers("/h2-console/**").denyAll()
                .mvcMatchers("/admin/**").hasRole(ADMIN_ROLE)
                .mvcMatchers("/api/admin/**").hasRole(ADMIN_ROLE)
                .anyRequest().fullyAuthenticated();

        // Logout configuration
        http.logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout**"))       // ログアウト処理のパス
                .logoutSuccessUrl("/login?logout=true");                                        // ログアウト完了時のパス


        // WebAuthn SecurityFilterChain
        http.apply(webAuthnLogin())
                .loginPage("/login")
                .usernameParameter("username")
                .passwordParameter("rawPassword")
                .webAuthnAuthenticationContextProvider(webAuthnAuthenticationContextProvider)
                .metadataProvider(metadataProvider);

        http.exceptionHandling();

        http.sessionManagement()
                .invalidSessionStrategy(invalidSessionStrategy)
                .invalidSessionUrl("/login?expired")
                .sessionAuthenticationErrorUrl("/login?expired");

        http.securityContext()
                .securityContextRepository(httpSessionSecurityContextRepository);

        http.exceptionHandling().accessDeniedHandler(accessDeniedHandler);


    }

}
