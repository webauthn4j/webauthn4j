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

        if(FIDOAppIDClientExtensionOutput.ID.getValue().equals(currentName)){
            return ctxt.readValue(p, FIDOAppIDClientExtensionOutput.class);
        }
        else if(SimpleTransactionAuthorizationClientExtensionOutput.ID.getValue().equals(currentName)){
            return ctxt.readValue(p, SimpleTransactionAuthorizationClientExtensionOutput.class);
        }
        else if(UserVerificationIndexClientExtensionOutput.ID.getValue().equals(currentName)){
            return ctxt.readValue(p, UserVerificationIndexClientExtensionOutput.class);
        }

        String parentName = p.getParsingContext().getParent().getCurrentName();

        if(GenericTransactionAuthorizationClientExtensionOutput.ID.getValue().equals(parentName)){
            return ctxt.readValue(p, GenericTransactionAuthorizationClientExtensionOutput.class);
        }
        else if (AuthenticatorSelectionClientExtensionOutput.ID.getValue().equals(parentName)) {
            return ctxt.readValue(p, AuthenticatorSelectionClientExtensionOutput.class);
        }
        else if (SupportedExtensionsClientExtensionOutput.ID.getValue().equals(parentName)) {
            return ctxt.readValue(p, SupportedExtensionsClientExtensionOutput.class);
        }
        else if (LocationClientExtensionOutput.ID.getValue().equals(parentName)) {
            return ctxt.readValue(p, LocationClientExtensionOutput.class);
        }
        else if (UserVerificationIndexClientExtensionOutput.ID.getValue().equals(parentName)) {
            return ctxt.readValue(p, UserVerificationIndexClientExtensionOutput.class);
        }
        else if(BiometricAuthenticatorPerformanceBoundsClientExtensionOutput.ID.getValue().equals(parentName)){
            return ctxt.readValue(p, BiometricAuthenticatorPerformanceBoundsClientExtensionOutput.class);
        }

        throw new NotImplementedException();
    }
}
