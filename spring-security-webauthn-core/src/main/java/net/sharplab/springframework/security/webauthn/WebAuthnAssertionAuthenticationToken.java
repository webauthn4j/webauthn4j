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

import com.webauthn4j.webauthn.context.WebAuthnAuthenticationContext;
import org.springframework.security.authentication.AbstractAuthenticationToken;

/**
 * WebAuthnAssertionAuthenticationToken
 */
public class WebAuthnAssertionAuthenticationToken extends AbstractAuthenticationToken {

    // ~ Instance fields
    // ================================================================================================

    private WebAuthnAuthenticationContext credentials;


    /**
     * This constructor can be safely used by any code that wishes to create a
     * <code>WebAuthnAssertionAuthenticationToken</code>, as the {@link #isAuthenticated()}
     * will return <code>false</code>.
     *
     * @param credentials credential
     */
    public WebAuthnAssertionAuthenticationToken(WebAuthnAuthenticationContext credentials) {
        super(null);
        this.credentials = credentials;
        setAuthenticated(false);
    }

    /**
     * Always null
     *
     * @return null
     */
    @Override
    public String getPrincipal() {
        return null;
    }

    /**
     * @return the stored WebAuthn authentication context
     */
    @Override
    public WebAuthnAuthenticationContext getCredentials() {
        return credentials;
    }

    /**
     * This object can never be authenticated, call with true result in exception.
     *
     * @param isAuthenticated only false value allowed
     * @throws IllegalArgumentException if isAuthenticated is true
     */
    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        if (isAuthenticated) {
            throw new IllegalArgumentException(
                    "Cannot set this token to trusted");
        }

        super.setAuthenticated(false);
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        credentials = null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof WebAuthnAssertionAuthenticationToken)) return false;
        if (!super.equals(o)) return false;

        WebAuthnAssertionAuthenticationToken that = (WebAuthnAssertionAuthenticationToken) o;

        return credentials != null ? credentials.equals(that.credentials) : that.credentials == null;
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + (credentials != null ? credentials.hashCode() : 0);
        return result;
    }
}
