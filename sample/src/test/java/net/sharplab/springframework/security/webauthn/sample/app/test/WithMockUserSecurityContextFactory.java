package net.sharplab.springframework.security.webauthn.sample.app.test;

import net.sharplab.springframework.security.webauthn.sample.domain.model.Authenticator;
import net.sharplab.springframework.security.webauthn.sample.domain.model.Authority;
import net.sharplab.springframework.security.webauthn.sample.domain.model.Group;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * SecurityContextFactory for WithMockUser
 */
public class WithMockUserSecurityContextFactory implements WithSecurityContextFactory<WithMockUser> {

    /**
     * Create a {@link SecurityContext} given an Annotation.
     *
     * @param user the {@link WithMockUser} to create the {@link SecurityContext}
     *                   from. Cannot be null.
     * @return the {@link SecurityContext} to use. Cannot be null.
     */
    @Override
    public SecurityContext createSecurityContext(WithMockUser user) {

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        List<Authority> authorities = Arrays.stream(user.authorities()).map(Authority::new).collect(Collectors.toList());
        List<Group> groups = Arrays.stream(user.groups()).map(Group::new).collect(Collectors.toList());
        List<Authenticator> authenticators = Arrays.stream(user.authenticators()).map(Authenticator::new).collect(Collectors.toList());

        User principal =
                new User(
                        user.id(),
                        user.userHandleString().getBytes(StandardCharsets.UTF_8),
                        user.firstName(),
                        user.lastName(),
                        user.emailAddress(),
                        authorities,
                        groups,
                        authenticators,
                        user.locked(),
                        user.passwordAuthenticationAllowed()
                );
        Authentication auth =
                new UsernamePasswordAuthenticationToken(principal, "password", principal.getAuthorities());
        context.setAuthentication(auth);
        return context;
    }
}
