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

package sample;

import com.webauthn4j.response.WebAuthnAuthenticationContext;
import com.webauthn4j.response.WebAuthnRegistrationContext;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.response.client.Origin;
import com.webauthn4j.response.client.challenge.Challenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;

public class Sample {

    public void registrationValidationSample() {
        // Client properties
        byte[] clientDataJSON = null /* set clientDataJSON */;
        byte[] attestationObject = null /* set attestationObject */;

        // Server properties
        Origin origin = null /* set origin */;
        String rpId = null /* set rpId */;
        Challenge challenge = null /* set challenge */;
        byte[] tokenBindingId = null /* set tokenBindingId */;
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);

        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(clientDataJSON, attestationObject, serverProperty, false);

        WebAuthnRegistrationContextValidator webAuthnRegistrationContextValidator =
                WebAuthnRegistrationContextValidator.createNonStrictRegistrationContextValidator();

        webAuthnRegistrationContextValidator.validate(registrationContext);
    }

    public void authenticationValidationSample() {
        // Client properties
        byte[] credentialId = null /* set credentialId */;
        byte[] clientDataJSON = null /* set clientDataJSON */;
        byte[] authenticatorData = null /* set authenticatorData */;
        byte[] signature = null /* set signature */;

        // Server properties
        Origin origin = null /* set origin */;
        String rpId = null /* set rpId */;
        Challenge challenge = null /* set challenge */;
        byte[] tokenBindingId = null /* set tokenBindingId */;
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);

        WebAuthnAuthenticationContext authenticationContext =
                new WebAuthnAuthenticationContext(
                        credentialId,
                        clientDataJSON,
                        authenticatorData,
                        signature,
                        serverProperty,
                        true
                );
        Authenticator authenticator = null /* set authenticator */;

        WebAuthnAuthenticationContextValidator webAuthnAuthenticationContextValidator =
                new WebAuthnAuthenticationContextValidator();

        webAuthnAuthenticationContextValidator.validate(authenticationContext, authenticator);
    }
}
