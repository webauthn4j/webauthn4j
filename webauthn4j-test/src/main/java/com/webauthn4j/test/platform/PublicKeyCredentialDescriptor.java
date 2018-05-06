package com.webauthn4j.test.platform;

import com.webauthn4j.util.WIP;

import java.util.Collections;
import java.util.List;

@WIP
public class PublicKeyCredentialDescriptor {
    private PublicKeyCredentialType type;
    private byte[] id;
    private List<AuthenticatorTransport> transports = Collections.emptyList();

    public PublicKeyCredentialDescriptor(PublicKeyCredentialType type, byte[] id, List<AuthenticatorTransport> transports) {
        this.type = type;
        this.id = id;
        this.transports = transports;
    }

    public PublicKeyCredentialType getType() {
        return type;
    }

    public byte[] getId() {
        return id;
    }

    public List<AuthenticatorTransport> getTransports() {
        return transports;
    }
}
