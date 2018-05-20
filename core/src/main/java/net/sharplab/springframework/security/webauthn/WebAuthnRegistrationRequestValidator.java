package net.sharplab.springframework.security.webauthn;

import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.WebAuthnRegistrationContext;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import net.sharplab.springframework.security.webauthn.context.provider.ServerPropertyProvider;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class WebAuthnRegistrationRequestValidator {

    private ServerPropertyProvider serverPropertyProvider;

    private WebAuthnRegistrationContextValidator registrationContextValidator;

    public WebAuthnRegistrationRequestValidator(WebAuthnRegistrationContextValidator registrationContextValidator, ServerPropertyProvider serverPropertyProvider) {
        this.registrationContextValidator = registrationContextValidator;
        this.serverPropertyProvider = serverPropertyProvider;
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

        byte[] clientDataBytes = Base64UrlUtil.decode(clientDataBase64);
        byte[] attestationObjectBytes = Base64UrlUtil.decode(attestationObjectBase64);
        ServerProperty serverProperty = serverPropertyProvider.provide(request, response);

        return new WebAuthnRegistrationContext(clientDataBytes, attestationObjectBytes, serverProperty);
    }

}
