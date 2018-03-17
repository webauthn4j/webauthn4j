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

package net.sharplab.springframework.security.webauthn.userdetails;

import net.sharplab.springframework.security.webauthn.authenticator.WebAuthnAuthenticator;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.List;

/**
 * A {@link WebAuthnUserDetails} implementation
 */
@SuppressWarnings("squid:S2160")
public class WebAuthnUserDetailsImpl extends User implements WebAuthnUserDetails {

    // ~ Instance fields
    // ================================================================================================
    private boolean passwordAuthenticationAllowed = false;
    private List<WebAuthnAuthenticator> authenticators;

    public WebAuthnUserDetailsImpl(String username, String password, List<WebAuthnAuthenticator> authenticators,
                                   Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
        this.authenticators = authenticators;
    }

    public WebAuthnUserDetailsImpl(String username, String password, List<WebAuthnAuthenticator> authenticators,
                                   Collection<? extends GrantedAuthority> authorities, boolean passwordAuthenticationAllowed) {
        this(username, password, authenticators, authorities);
        this.passwordAuthenticationAllowed = passwordAuthenticationAllowed;
    }

    @Override
    public List<WebAuthnAuthenticator> getAuthenticators() {
        return this.authenticators;
    }

    @Override
    public boolean isPasswordAuthenticationAllowed(){
        return passwordAuthenticationAllowed;
    }

    @Override
    public void setPasswordAuthenticationAllowed(boolean passwordAuthenticationAllowed) {
        this.passwordAuthenticationAllowed = passwordAuthenticationAllowed;
    }


}
