package com.webauthn4j.converter.jackson.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.webauthn4j.extension.*;
import com.webauthn4j.util.exception.NotImplementedException;

import java.io.IOException;

public class ExtensionOutputDeserializer extends StdDeserializer<ExtensionOutput> {

    public ExtensionOutputDeserializer() {
        super(ExtensionOutput.class);
    }

    @Override
    public ExtensionOutput deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {

        String currentName = p.getParsingContext().getCurrentName();

        if(FIDOAppIDExtensionOutput.ID.getValue().equals(currentName)){
            return ctxt.readValue(p, FIDOAppIDExtensionOutput.class);
        }
        else if(SimpleTransactionAuthorizationExtensionOutput.ID.getValue().equals(currentName)){
            return ctxt.readValue(p, SimpleTransactionAuthorizationExtensionOutput.class);
        }
        else if(UserVerificationIndexExtensionOutput.ID.getValue().equals(currentName)){
            return ctxt.readValue(p, UserVerificationIndexExtensionOutput.class);
        }

        String parentName = p.getParsingContext().getParent().getCurrentName();

        if(GenericTransactionAuthorizationExtensionOutput.ID.getValue().equals(parentName)){
            return ctxt.readValue(p, GenericTransactionAuthorizationExtensionOutput.class);
        }
        else if (AuthenticatorSelectionExtensionOutput.ID.getValue().equals(parentName)) {
            return ctxt.readValue(p, AuthenticatorSelectionExtensionOutput.class);
        }
        else if (SupportedExtensionsExtensionOutput.ID.getValue().equals(parentName)) {
            return ctxt.readValue(p, SupportedExtensionsExtensionOutput.class);
        }
        else if (LocationExtensionOutput.ID.getValue().equals(parentName)) {
            return ctxt.readValue(p, LocationExtensionOutput.class);
        }
        else if (UserVerificationIndexExtensionOutput.ID.getValue().equals(parentName)) {
            return ctxt.readValue(p, UserVerificationIndexExtensionOutput.class);
        }
        else if(BiometricAuthenticatorPerformanceBoundsExtensionOutput.ID.getValue().equals(parentName)){
            return ctxt.readValue(p, BiometricAuthenticatorPerformanceBoundsExtensionOutput.class);
        }

        throw new NotImplementedException();
    }
}
