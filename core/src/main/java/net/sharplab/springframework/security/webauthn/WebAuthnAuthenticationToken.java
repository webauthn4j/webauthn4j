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

import net.sharplab.springframework.security.webauthn.context.WebAuthnAuthenticationContext;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;
import java.util.Collection;

/**
 * An {@link org.springframework.security.core.Authentication} implementation that is
 * designed for Web Authentication specification.
 */
public class WebAuthnAuthenticationToken extends AbstractAuthenticationToken {

    private Serializable principal;
    private WebAuthnAuthenticationContext credentials;

    public WebAuthnAuthenticationToken(Serializable principal, WebAuthnAuthenticationContext credentials, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        this.setAuthenticated(true);
    }

    @Override
    public Serializable getPrincipal() {
        return principal;
    }

    @Override
    public WebAuthnAuthenticationContext getCredentials() {
        return credentials;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof WebAuthnAuthenticationToken)) return false;
        if (!super.equals(o)) return false;

        WebAuthnAuthenticationToken that = (WebAuthnAuthenticationToken) o;

        if (principal != null ? !principal.equals(that.principal) : that.principal != null) return false;
        return credentials != null ? credentials.equals(that.credentials) : that.credentials == null;
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + (principal != null ? principal.hashCode() : 0);
        result = 31 * result + (credentials != null ? credentials.hashCode() : 0);
        return result;
    }
}
