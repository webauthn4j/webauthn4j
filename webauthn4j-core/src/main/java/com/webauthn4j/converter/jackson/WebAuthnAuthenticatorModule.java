package com.webauthn4j.converter.jackson;

import com.fasterxml.jackson.databind.jsontype.NamedType;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.webauthn4j.converter.jackson.deserializer.*;
import com.webauthn4j.data.extension.authenticator.ExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.authenticator.SupportedExtensionsExtensionAuthenticatorOutput;

public class WebAuthnAuthenticatorModule extends SimpleModule {
    public WebAuthnAuthenticatorModule() {
        super("WebAuthnAuthenticatorModule");

        this.addDeserializer(CredentialPublicKeyEnvelope.class, new CredentialPublicKeyEnvelopeDeserializer());
        this.addDeserializer(AuthenticationExtensionsAuthenticatorOutputsEnvelope.class, new AuthenticationExtensionsAuthenticatorOutputsEnvelopeDeserializer());
        this.addDeserializer(ExtensionAuthenticatorOutput.class, new ExtensionAuthenticatorOutputDeserializer());

        this.registerSubtypes(new NamedType(SupportedExtensionsExtensionAuthenticatorOutput.class, SupportedExtensionsExtensionAuthenticatorOutput.ID));
    }
}
