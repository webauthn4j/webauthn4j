package net.sharplab.springframework.security.webauthn.sample.app.web;

import net.sharplab.springframework.security.webauthn.context.WebAuthnRegistrationContext;
import net.sharplab.springframework.security.webauthn.context.provider.WebAuthnRegistrationContextProvider;
import net.sharplab.springframework.security.webauthn.context.validator.WebAuthnRegistrationContextValidator;
import net.sharplab.springframework.security.webauthn.exception.BadChallengeException;
import net.sharplab.springframework.security.webauthn.sample.domain.constant.MessageCodes;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ui.Model;
import org.terasoluna.gfw.common.message.ResultMessages;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

/**
 * Created by ynojima on 2017/09/13.
 */
public class UserHelper {

    private WebAuthnRegistrationContextProvider registrationContextProvider;
    private WebAuthnRegistrationContextValidator registrationContextValidator;

    @Autowired
    public UserHelper(WebAuthnRegistrationContextProvider registrationContextProvider,
                          WebAuthnRegistrationContextValidator registrationContextValidator) {
        this.registrationContextProvider = registrationContextProvider;
        this.registrationContextValidator = registrationContextValidator;
    }

     /**
     * returns true if validation success
     * @param model model
     * @param request request
     * @param response reponse
     * @param authenticatorForms authenticator form list
     * @return true if validation success
     */
    public boolean validateAuthenticators(Model model, HttpServletRequest request, HttpServletResponse response, List<AuthenticatorForm> authenticatorForms) {
        if (authenticatorForms == null) {
            return true;
        }
        boolean allValid = authenticatorForms.stream().allMatch(authenticator -> {
            try{
                WebAuthnRegistrationContext registrationContext = registrationContextProvider.provide(
                        request,
                        response,
                        authenticator.getClientData().getClientDataBase64(),
                        authenticator.getAttestationObject().getAttestationObjectBase64());
                registrationContextValidator.validate(registrationContext);
                return true;
            }
            catch (BadChallengeException e){
                model.addAttribute(ResultMessages.error().add(MessageCodes.Error.User.BAD_CHALLENGE));
                return false;
            }
        });
        return allValid;
    }
}
