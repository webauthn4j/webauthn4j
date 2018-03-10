package net.sharplab.springframework.security.webauthn.metadata;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.sharplab.springframework.security.webauthn.authenticator.WebAuthnAuthenticator;
import net.sharplab.springframework.security.webauthn.exception.MetadataException;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.apache.commons.codec.binary.Base64;
import org.springframework.util.Base64Utils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class MetadataProviderImpl implements MetadataProvider{

    private WebAuthnUserDetailsService userDetailsService;

    private ObjectMapper objectMapper = new ObjectMapper();

    public MetadataProviderImpl(WebAuthnUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    public String getMetadataAsString(String username) throws MetadataException {
        try {
            Collection<? extends WebAuthnAuthenticator> authenticators = userDetailsService.loadUserByUsername(username).getAuthenticators();
            List<Metadata> metadataList = new ArrayList<>();
            for(WebAuthnAuthenticator authenticator : authenticators){
                String credentialIdStr = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(authenticator.getAttestationData().getCredentialId());
                Metadata metadata = new Metadata();
                metadata.setCredentialId(credentialIdStr);
                metadataList.add(metadata);
            }
            return objectMapper.writeValueAsString(metadataList);
        }
        catch (IOException | RuntimeException e) {
            throw new MetadataException(e);
        }
    }

}
