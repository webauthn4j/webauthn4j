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

package net.sharplab.springframework.security.webauthn.authenticator;

import com.webauthn4j.webauthn.authenticator.WebAuthnAuthenticator;
import net.sharplab.springframework.security.webauthn.exception.CredentialIdNotFoundException;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * Web Authentication specialized {@link UserDetailsService}
 */
public interface WebAuthnAuthenticatorService {

    /**
     * Locates the user based on the username. In the actual implementation, the search may possibly be case
     * insensitive, or case insensitive depending on how the implementation instance is configured. In this case, the
     * <code>UserDetails</code> object that comes back may have a username that is of a different case than what was
     * actually requested..
     *
     * @param credentialId the credentialId identifying the user whose data is required.
     * @return a fully populated user record (never <code>null</code>)
     * @throws CredentialIdNotFoundException if the user could not be found or the user has no GrantedAuthority
     */
    WebAuthnAuthenticator loadWebAuthnAuthenticatorByCredentialId(byte[] credentialId);

}
