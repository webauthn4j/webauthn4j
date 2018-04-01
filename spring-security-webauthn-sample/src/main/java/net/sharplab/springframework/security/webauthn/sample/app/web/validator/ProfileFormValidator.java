package net.sharplab.springframework.security.webauthn.sample.app.web.validator;

import net.sharplab.springframework.security.webauthn.sample.app.web.ProfileForm;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

@Component
public class ProfileFormValidator implements Validator {
    @Override
    public boolean supports(Class<?> clazz) {
        return ProfileForm.class.isAssignableFrom(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        ProfileForm form = (ProfileForm) target;

        int authenticatorCount = 0;
        if(form.getNewAuthenticators() != null){
            authenticatorCount += form.getNewAuthenticators().stream().filter(item -> !item.isDelete()).count();
        }
        if(form.getAuthenticators() != null){
            authenticatorCount += form.getAuthenticators().stream().filter(item -> !item.isDelete()).count();
        }

        if(!form.isPasswordAuthenticationAllowed() && authenticatorCount == 0){
            errors.rejectValue("newAuthenticators",
                    "e.ProfileFormValidator.noAuthenticator",
                    "To disable password authentication, at least one authenticator must be registered.");
        }
    }
}