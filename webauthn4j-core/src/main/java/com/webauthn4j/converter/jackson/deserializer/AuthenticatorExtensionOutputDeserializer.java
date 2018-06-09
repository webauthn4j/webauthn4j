package com.webauthn4j.converter.jackson.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.webauthn4j.extension.authneticator.*;
import com.webauthn4j.util.exception.NotImplementedException;

import java.io.IOException;

public class AuthenticatorExtensionOutputDeserializer extends StdDeserializer<AuthenticatorExtensionOutput> {

    public AuthenticatorExtensionOutputDeserializer() {
        super(AuthenticatorExtensionOutput.class);
    }

    @Override
    public AuthenticatorExtensionOutput deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {

        String currentName = p.getParsingContext().getCurrentName();

        if(SimpleTransactionAuthorizationAuthenticatorExtensionOutput.ID.equals(currentName)){
            return ctxt.readValue(p, SimpleTransactionAuthorizationAuthenticatorExtensionOutput.class);
        }
        else if(UserVerificationIndexAuthenticatorExtensionOutput.ID.equals(currentName)){
            return ctxt.readValue(p, UserVerificationIndexAuthenticatorExtensionOutput.class);
        }

        String parentName = p.getParsingContext().getParent().getCurrentName();

        if(GenericTransactionAuthorizationAuthenticatorExtensionOutput.ID.equals(parentName)){
            return ctxt.readValue(p, GenericTransactionAuthorizationAuthenticatorExtensionOutput.class);
        }
        else if (SupportedExtensionsAuthenticatorExtensionOutput.ID.equals(parentName)) {
            return ctxt.readValue(p, SupportedExtensionsAuthenticatorExtensionOutput.class);
        }
        else if (LocationAuthenticatorExtensionOutput.ID.equals(parentName)) {
            return ctxt.readValue(p, LocationAuthenticatorExtensionOutput.class);
        }
        else if (UserVerificationIndexAuthenticatorExtensionOutput.ID.equals(parentName)) {
            return ctxt.readValue(p, UserVerificationIndexAuthenticatorExtensionOutput.class);
        }

        throw new NotImplementedException();
    }
}
