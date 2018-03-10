package net.sharplab.springframework.security.webauthn.metadata;

public interface MetadataProvider {

    String getMetadataAsString(String username);
}
