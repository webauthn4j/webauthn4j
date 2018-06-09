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

package com.webauthn4j.converter.jackson.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.webauthn4j.extension.client.*;
import com.webauthn4j.util.exception.NotImplementedException;

import java.io.IOException;

public class ClientExtensionOutputDeserializer extends StdDeserializer<ClientExtensionOutput> {

    public ClientExtensionOutputDeserializer() {
        super(ClientExtensionOutput.class);
    }

    @Override
    public ClientExtensionOutput deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {

        String currentName = p.getParsingContext().getCurrentName();

        if (FIDOAppIDClientExtensionOutput.ID.equals(currentName)) {
            return ctxt.readValue(p, FIDOAppIDClientExtensionOutput.class);
        } else if (SimpleTransactionAuthorizationClientExtensionOutput.ID.equals(currentName)) {
            return ctxt.readValue(p, SimpleTransactionAuthorizationClientExtensionOutput.class);
        } else if (UserVerificationIndexClientExtensionOutput.ID.equals(currentName)) {
            return ctxt.readValue(p, UserVerificationIndexClientExtensionOutput.class);
        }

        String parentName = p.getParsingContext().getParent().getCurrentName();

        if (GenericTransactionAuthorizationClientExtensionOutput.ID.equals(parentName)) {
            return ctxt.readValue(p, GenericTransactionAuthorizationClientExtensionOutput.class);
        } else if (AuthenticatorSelectionClientExtensionOutput.ID.equals(parentName)) {
            return ctxt.readValue(p, AuthenticatorSelectionClientExtensionOutput.class);
        } else if (SupportedExtensionsClientExtensionOutput.ID.equals(parentName)) {
            return ctxt.readValue(p, SupportedExtensionsClientExtensionOutput.class);
        } else if (LocationClientExtensionOutput.ID.equals(parentName)) {
            return ctxt.readValue(p, LocationClientExtensionOutput.class);
        } else if (UserVerificationIndexClientExtensionOutput.ID.equals(parentName)) {
            return ctxt.readValue(p, UserVerificationIndexClientExtensionOutput.class);
        } else if (BiometricAuthenticatorPerformanceBoundsClientExtensionOutput.ID.equals(parentName)) {
            return ctxt.readValue(p, BiometricAuthenticatorPerformanceBoundsClientExtensionOutput.class);
        }

        throw new NotImplementedException();
    }
}
