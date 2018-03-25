package net.sharplab.springframework.security.webauthn.sample.app.web.helper;

import net.sharplab.springframework.security.webauthn.sample.app.web.AuthenticatorCreateForm;
import net.sharplab.springframework.security.webauthn.sample.app.web.AuthenticatorUpdateForm;
import net.sharplab.springframework.security.webauthn.sample.app.web.admin.UserCreateForm;
import net.sharplab.springframework.security.webauthn.sample.app.web.admin.UserPasswordForm;
import net.sharplab.springframework.security.webauthn.sample.app.web.admin.UserUpdateForm;
import net.sharplab.springframework.security.webauthn.sample.domain.model.Authenticator;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.util.Base64Utils;

import javax.validation.Valid;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Helper class for user management
 */
@Component
public class UserHelper {

    private AuthenticatorHelper authenticatorHelper;
    private PasswordEncoder passwordEncoder;

    @Autowired
    public UserHelper(
            AuthenticatorHelper authenticatorHelper,
            PasswordEncoder passwordEncoder) {
        this.authenticatorHelper = authenticatorHelper;
        this.passwordEncoder = passwordEncoder;
    }

    public UserUpdateForm map(User source, UserUpdateForm destination){
        if (destination == null) {
            destination = new UserUpdateForm();
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
        destination.setLocked(source.isLocked());
        destination.setPasswordAuthenticationAllowed(source.isPasswordAuthenticationAllowed());
        return destination;
    }

    public UserPasswordForm map(User source, UserPasswordForm destination) {
        if(destination == null){
            destination = new UserPasswordForm();
        }
        destination.setEmailAddress(source.getEmailAddress());
        return destination;
    }

    public User mapForCreate(UserCreateForm source){
        if(source.getNewAuthenticators() == null){
            source.setNewAuthenticators(new ArrayList<>());
        }
        User destination = new User();
        if(destination.getAuthenticators() == null){
            destination.setAuthenticators(new ArrayList<>());
        }


        destination.setUserHandle(Base64Utils.decodeFromUrlSafeString(source.getUserHandle()));
        destination.setFirstName(source.getFirstName());
        destination.setLastName(source.getLastName());
        destination.setEmailAddress(source.getEmailAddress());
        destination.setPassword(passwordEncoder.encode(source.getRawPassword()));

        List<AuthenticatorCreateForm> authenticatorCreateForms = source.getNewAuthenticators().stream()
                .filter(authenticatorCreateForm -> !authenticatorCreateForm.isDelete()).collect(Collectors.toList());
        List<Authenticator> authenticators = new ArrayList<>();

        for(AuthenticatorCreateForm authenticatorCreateForm : authenticatorCreateForms){
            authenticators.add(authenticatorHelper.mapForUpdate(authenticatorCreateForm, null));
        }
        destination.setAuthenticators(authenticators);
        destination.setLocked(source.isLocked());
        destination.setPasswordAuthenticationAllowed(source.isPasswordAuthenticationAllowed());

        return destination;

    }

    public User mapForUpdate(UserUpdateForm source, User destination) {
        if (source.getAuthenticators() == null) {
            source.setAuthenticators(new ArrayList<>());
        }
        if(source.getNewAuthenticators() == null){
            source.setNewAuthenticators(new ArrayList<>());
        }
        if(destination.getAuthenticators() == null){
            destination.setAuthenticators(new ArrayList<>());
        }


        // don't update userHandle
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
        destination.setLocked(source.isLocked());
        destination.setPasswordAuthenticationAllowed(source.isPasswordAuthenticationAllowed());

        return destination;
    }


    public User mapForUpdate(UserPasswordForm source, User destination) {
        // don't update everything except password
        destination.setPassword(passwordEncoder.encode(source.getRawPassword()));

        return destination;
    }

}
