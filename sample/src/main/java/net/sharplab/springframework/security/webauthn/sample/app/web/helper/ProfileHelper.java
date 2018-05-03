package net.sharplab.springframework.security.webauthn.sample.app.web.helper;

import net.sharplab.springframework.security.webauthn.sample.app.web.AuthenticatorCreateForm;
import net.sharplab.springframework.security.webauthn.sample.app.web.AuthenticatorUpdateForm;
import net.sharplab.springframework.security.webauthn.sample.app.web.ProfileForm;
import net.sharplab.springframework.security.webauthn.sample.app.web.ProfilePasswordForm;
import net.sharplab.springframework.security.webauthn.sample.domain.model.Authenticator;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class ProfileHelper {

    @Autowired
    AuthenticatorHelper authenticatorHelper;

    @Autowired
    PasswordEncoder passwordEncoder;

    public ProfileForm map(User source, ProfileForm destination){
        if (destination == null) {
            destination = new ProfileForm();
        }

        byte[] sourceUserHandle = source.getUserHandle();
        if (sourceUserHandle == null) {
            destination.setUserHandle(null);
        } else {
            destination.setUserHandle(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(sourceUserHandle));
        }
        destination.setFirstName(source.getFirstName());
        destination.setLastName(source.getLastName());
        destination.setEmailAddress(source.getEmailAddress());
        if (source.getAuthenticators() == null) {
            destination.setAuthenticators(null);
        } else {
            List<AuthenticatorUpdateForm> authenticatorUpdateForms = source.getAuthenticators().stream().map(authenticator ->
                    authenticatorHelper.mapForUpdate(authenticator, null)).collect(Collectors.toList());
            destination.setAuthenticators(authenticatorUpdateForms);
        }
        destination.setPasswordAuthenticationAllowed(source.isPasswordAuthenticationAllowed());
        return destination;

    }

    public User mapForUpdate(ProfileForm source, User destination){
        if (source.getAuthenticators() == null) {
            source.setAuthenticators(new ArrayList<>());
        }
        if(source.getNewAuthenticators() == null){
            source.setNewAuthenticators(new ArrayList<>());
        }
        if (destination == null) {
            destination = new User();
        }
        if(destination.getAuthenticators() == null){
            destination.setAuthenticators(new ArrayList<>());
        }


        // don't update userHandle when updating user
        destination.setFirstName(source.getFirstName());
        destination.setLastName(source.getLastName());
        destination.setEmailAddress(source.getEmailAddress());

        List<AuthenticatorCreateForm> authenticatorCreateForms = source.getNewAuthenticators().stream()
                .filter(authenticatorCreateForm -> !authenticatorCreateForm.isDelete()).collect(Collectors.toList());
        List<AuthenticatorUpdateForm> authenticatorUpdateForms = source.getAuthenticators().stream()
                .filter(authenticatorCreateForm -> !authenticatorCreateForm.isDelete()).collect(Collectors.toList());
        List<Authenticator> originalAuthenticators = destination.getAuthenticators();
        List<Authenticator> authenticators = new ArrayList<>();

        for(AuthenticatorUpdateForm authenticatorUpdateForm : authenticatorUpdateForms){
            originalAuthenticators
                    .stream()
                    .filter(originalAuthenticator -> originalAuthenticator.getId().equals(authenticatorUpdateForm.getId()))
                    .findFirst().ifPresent(originalAuthenticator -> {
                authenticatorHelper.mapForUpdate(authenticatorUpdateForm, originalAuthenticator);
                authenticators.add(originalAuthenticator);
            });
        }
        for(AuthenticatorCreateForm authenticatorCreateForm : authenticatorCreateForms){
            authenticators.add(authenticatorHelper.mapForUpdate(authenticatorCreateForm, null));
        }
        destination.setAuthenticators(authenticators);
        destination.setPasswordAuthenticationAllowed(source.isPasswordAuthenticationAllowed());

        return destination;

    }

    public ProfilePasswordForm map(User source, ProfilePasswordForm destination){
        if(destination == null){
            destination = new ProfilePasswordForm();
        }

        // carry emailAddress only. Leave rawPassword and rawPasswordRetyped as it is.
        destination.setEmailAddress(source.getEmailAddress());
        return destination;
    }

    public User mapForUpdate(ProfilePasswordForm source, User destination){
        if (destination == null) {
            destination = new User();
        }

        // carry password only. Leave emailAddress as it is.
        destination.setPassword(passwordEncoder.encode(source.getRawPassword()));
        return destination;
    }
}
