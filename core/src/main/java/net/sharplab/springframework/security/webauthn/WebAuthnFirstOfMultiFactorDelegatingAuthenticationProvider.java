/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.authentication.FirstOfMultiFactorAuthenticationToken;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation for the first of multi factor authentication.
 * Authentication itself is delegated to {@link AbstractUserDetailsAuthenticationProvider}.
 */
public class WebAuthnFirstOfMultiFactorDelegatingAuthenticationProvider implements AuthenticationProvider {



    // ~ Instance fields
    // ================================================================================================
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
    private AbstractUserDetailsAuthenticationProvider authenticationProvider;


    public WebAuthnFirstOfMultiFactorDelegatingAuthenticationProvider(AbstractUserDetailsAuthenticationProvider authenticationProvider){
        Assert.notNull(authenticationProvider, "Authentication provider must be set");
        this.authenticationProvider = authenticationProvider;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            throw new IllegalArgumentException("Only FirstOfMultiFactorAuthenticationToken is supported, " + authentication.getClass() + " was attempted");
        }

        FirstOfMultiFactorAuthenticationToken firstOfMultiFactorAuthenticationToken = (FirstOfMultiFactorAuthenticationToken)authentication;
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(firstOfMultiFactorAuthenticationToken.getPrincipal(), firstOfMultiFactorAuthenticationToken.getCredentials());

        Authentication result =  authenticationProvider.authenticate(usernamePasswordAuthenticationToken);

        return new FirstOfMultiFactorAuthenticationToken(result.getPrincipal(), result.getCredentials(), authentication.getAuthorities());
    }



    @Override
    public boolean supports(Class<?> authentication) {
        return FirstOfMultiFactorAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
