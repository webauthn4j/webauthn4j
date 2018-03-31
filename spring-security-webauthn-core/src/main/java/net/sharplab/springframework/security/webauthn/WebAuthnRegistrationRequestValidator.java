package net.sharplab.springframework.security.webauthn;

import com.webauthn4j.webauthn.context.RelyingParty;
import com.webauthn4j.webauthn.context.WebAuthnRegistrationContext;
import com.webauthn4j.webauthn.context.validator.WebAuthnRegistrationContextValidator;
import net.sharplab.springframework.security.webauthn.context.provider.RelyingPartyProvider;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Base64;

public class WebAuthnRegistrationRequestValidator {

    private RelyingPartyProvider relyingPartyProvider;

    private WebAuthnRegistrationContextValidator registrationContextValidator;

    public WebAuthnRegistrationRequestValidator(WebAuthnRegistrationContextValidator registrationContextValidator, RelyingPartyProvider relyingPartyProvider) {
        this.registrationContextValidator = registrationContextValidator;
        this.relyingPartyProvider = relyingPartyProvider;
    }

    public void validate(HttpServletRequest request, HttpServletResponse response,
                         String clientDataBase64,
                         String attestationObjectBase64) {
        WebAuthnRegistrationContext registrationContext = getRegistrationContext(request, response, clientDataBase64, attestationObjectBase64);
        registrationContextValidator.validate(registrationContext);
    }

    WebAuthnRegistrationContext getRegistrationContext(HttpServletRequest request, HttpServletResponse response,
                                                       String clientDataBase64,
                                                       String attestationObjectBase64) {

        byte[] clientDataBytes = Base64.getUrlDecoder().decode(clientDataBase64);
        byte[] attestationObjectBytes = Base64.getUrlDecoder().decode(attestationObjectBase64);
        RelyingParty relyingParty = relyingPartyProvider.provide(request, response);

        return new WebAuthnRegistrationContext(clientDataBytes, attestationObjectBytes, relyingParty);
    }

}
