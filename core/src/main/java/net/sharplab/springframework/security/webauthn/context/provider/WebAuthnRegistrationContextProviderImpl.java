package net.sharplab.springframework.security.webauthn.context.provider;

import net.sharplab.springframework.security.webauthn.attestation.WebAuthnAttestationObject;
import net.sharplab.springframework.security.webauthn.client.ClientData;
import net.sharplab.springframework.security.webauthn.context.RelyingParty;
import net.sharplab.springframework.security.webauthn.context.WebAuthnRegistrationContext;
import net.sharplab.springframework.security.webauthn.converter.Base64StringToClientDataConverter;
import net.sharplab.springframework.security.webauthn.converter.Base64StringToWebAuthnAttestationObjectConverter;
import org.springframework.util.Base64Utils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * {@inheritDoc}
 */
public class WebAuthnRegistrationContextProviderImpl implements WebAuthnRegistrationContextProvider {

    private Base64StringToClientDataConverter base64StringToClientDataConverter;
    private Base64StringToWebAuthnAttestationObjectConverter base64StringToWebAuthnAttestationObjectConverter;
    private RelyingPartyProvider relyingPartyProvider;

    public WebAuthnRegistrationContextProviderImpl(RelyingPartyProvider relyingPartyProvider){
        base64StringToClientDataConverter = new Base64StringToClientDataConverter();
        base64StringToWebAuthnAttestationObjectConverter = new Base64StringToWebAuthnAttestationObjectConverter();
        this.relyingPartyProvider = relyingPartyProvider;
    }

    public WebAuthnRegistrationContext provide(HttpServletRequest request, HttpServletResponse response,
                                               String clientDataBase64,
                                               String attestationObjectBase64){

        ClientData clientData = base64StringToClientDataConverter.convert(clientDataBase64);
        byte[] clientDataBytes = Base64Utils.decodeFromUrlSafeString(clientDataBase64);
        WebAuthnAttestationObject attestationObject = base64StringToWebAuthnAttestationObjectConverter.convert(attestationObjectBase64);
        byte[] attestationObjectBytes = Base64Utils.decodeFromUrlSafeString(attestationObjectBase64);
        RelyingParty relyingParty = relyingPartyProvider.provide(request, response);

        return new WebAuthnRegistrationContext(clientData, clientDataBytes, attestationObject, attestationObjectBytes, relyingParty);
    }

}
