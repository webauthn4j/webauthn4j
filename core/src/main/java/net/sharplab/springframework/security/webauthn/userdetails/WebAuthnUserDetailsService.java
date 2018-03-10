package net.sharplab.springframework.security.webauthn.userdetails;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public interface WebAuthnUserDetailsService extends UserDetailsService {

    WebAuthnUserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
