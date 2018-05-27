package com.webauthn4j.validator;

import com.webauthn4j.extension.ExtensionIdentifier;
import com.webauthn4j.extension.authneticator.AuthenticatorExtensionOutput;
import com.webauthn4j.extension.client.ClientExtensionOutput;
import com.webauthn4j.validator.exception.UnexpectedExtensionException;

import java.util.List;
import java.util.Map;

public class ExtensionValidator {

    public void validate(Map<ExtensionIdentifier, ClientExtensionOutput> clientExtensionOutputs,
                         Map<ExtensionIdentifier, AuthenticatorExtensionOutput> authenticatorExtensionOutputs,
                         List<ExtensionIdentifier> expectedExtensionIdentifiers) {
        if(clientExtensionOutputs != null){
            clientExtensionOutputs.keySet().forEach( identifier -> {
                if(!expectedExtensionIdentifiers.contains(identifier)){
                    throw new UnexpectedExtensionException(String.format("Unexpected client extension '%s' is contained", identifier.getValue()));
                }
            });
        }
        if(authenticatorExtensionOutputs != null){
            authenticatorExtensionOutputs.keySet().forEach( identifier -> {
                if(!expectedExtensionIdentifiers.contains(identifier)){
                    throw new UnexpectedExtensionException(String.format("Unexpected authenticator extension '%s' is contained", identifier.getValue()));
                }
            });
        }
    }
}
