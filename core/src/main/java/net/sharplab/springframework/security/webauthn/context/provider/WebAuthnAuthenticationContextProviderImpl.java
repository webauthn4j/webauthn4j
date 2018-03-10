package net.sharplab.springframework.security.webauthn.context.provider;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.sharplab.springframework.security.webauthn.attestation.authenticator.WebAuthnAuthenticatorData;
import net.sharplab.springframework.security.webauthn.client.ClientData;
import net.sharplab.springframework.security.webauthn.client.challenge.HttpSessionChallengeRepository;
import net.sharplab.springframework.security.webauthn.context.RelyingParty;
import net.sharplab.springframework.security.webauthn.context.WebAuthnAuthenticationContext;
import net.sharplab.springframework.security.webauthn.util.jackson.WebAuthnModule;
import net.sharplab.springframework.security.webauthn.util.jackson.deserializer.WebAuthnAuthenticatorDataDeserializer;
import org.springframework.security.core.Authentication;
import org.springframework.util.Base64Utils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

/**
 * {@inheritDoc}
 */
@SuppressWarnings("squid:S1609")
public class WebAuthnAuthenticationContextProviderImpl implements WebAuthnAuthenticationContextProvider {


    private ObjectMapper objectMapper;
    private WebAuthnAuthenticatorDataDeserializer deserializer;
    private RelyingPartyProvider relyingPartyProvider;

    public WebAuthnAuthenticationContextProviderImpl(RelyingPartyProvider relyingPartyProvider){
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new WebAuthnModule());
        this.deserializer = new WebAuthnAuthenticatorDataDeserializer();
        this.relyingPartyProvider = relyingPartyProvider;
    }


    @Override
    public WebAuthnAuthenticationContext provide(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 String credentialId,
                                                 String clientData,
                                                 String authenticatorData,
                                                 String signature,
                                                 Authentication currentAuthentication) {

        byte[] rawClientData = Base64Utils.decodeFromUrlSafeString(clientData);
        byte[] rawAuthenticatorData = Base64Utils.decodeFromUrlSafeString(authenticatorData);
        byte[] signatureBytes = Base64Utils.decodeFromUrlSafeString(signature);

        String clientDataJson = deriveClientDataJson(rawClientData);
        ClientData clientDataObject = deriveClientData(clientDataJson);
        WebAuthnAuthenticatorData authenticatorDataObject = deriveAuthenticatorData(rawAuthenticatorData);
        RelyingParty relyingParty = relyingPartyProvider.provide(request, response);

        return new WebAuthnAuthenticationContext(
                credentialId,
                rawClientData,
                rawAuthenticatorData,
                clientDataJson,
                clientDataObject,
                authenticatorDataObject,
                signatureBytes,
                relyingParty,
                currentAuthentication);
    }

    public RelyingPartyProvider getRelyingPartyProvider() {
        return relyingPartyProvider;
    }

    public void setRelyingPartyProvider(RelyingPartyProvider relyingPartyProvider) {
        this.relyingPartyProvider = relyingPartyProvider;
    }

    String deriveClientDataJson(byte[] rawClientData) {
        return new String(rawClientData, StandardCharsets.UTF_8); //TODO: UTF-8?
    }

    ClientData deriveClientData(String clientDataJson) {
        try {
            String trimmedClientDataJson = clientDataJson.replace("\0", "").trim();
            return objectMapper.readValue(trimmedClientDataJson, ClientData.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    WebAuthnAuthenticatorData deriveAuthenticatorData(byte[] rawAuthenticatorData) {
        return deserializer.deserialize(rawAuthenticatorData);
    }

}
