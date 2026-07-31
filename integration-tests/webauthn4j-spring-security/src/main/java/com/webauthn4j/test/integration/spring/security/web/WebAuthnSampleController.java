/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.test.integration.spring.security.web;

import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.springframework.security.WebAuthnRegistrationRequestValidationResponse;
import com.webauthn4j.springframework.security.WebAuthnRegistrationRequestValidator;
import com.webauthn4j.springframework.security.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.credential.WebAuthnCredentialRecord;
import com.webauthn4j.springframework.security.credential.WebAuthnCredentialRecordImpl;
import com.webauthn4j.springframework.security.credential.WebAuthnCredentialRecordManager;
import com.webauthn4j.springframework.security.exception.PrincipalNotFoundException;
import com.webauthn4j.springframework.security.exception.WebAuthnAuthenticationException;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.UUIDUtil;
import com.webauthn4j.util.exception.WebAuthnException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@SuppressWarnings("SameReturnValue")
@Controller
public class WebAuthnSampleController {

    private final Log logger = LogFactory.getLog(getClass());

    private static final String REDIRECT_LOGIN = "redirect:/login";

    private static final String VIEW_SIGNUP_SIGNUP = "signup/signup";

    private static final String VIEW_DASHBOARD_DASHBOARD = "dashboard/dashboard";

    private static final String VIEW_LOGIN_LOGIN = "login/login";

    private static final String VIEW_LOGIN_AUTHENTICATOR_LOGIN = "login/authenticator-login";

    @Autowired
    private UserDetailsManager userDetailsManager;

    @Autowired
    private WebAuthnCredentialRecordManager webAuthnAuthenticatorManager;

    @Autowired
    private WebAuthnRegistrationRequestValidator registrationRequestValidator;

    @Autowired
    private ChallengeRepository challengeRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private final AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();

    @ModelAttribute
    public void addAttributes(Model model, HttpServletRequest request) {
        Challenge challenge = challengeRepository.loadOrGenerateChallenge(request);
        model.addAttribute("webAuthnChallenge", Base64UrlUtil.encodeToString(challenge.getValue()));
        model.addAttribute("webAuthnCredentialIds", getCredentialIds());
    }

    @GetMapping(value = "/")
    public String index() {
        return VIEW_DASHBOARD_DASHBOARD;
    }

    @GetMapping(value = "/signup")
    public String template(Model model) {
        UserCreateForm userCreateForm = new UserCreateForm();
        UUID userHandle = UUID.randomUUID();
        String userHandleStr = Base64UrlUtil.encodeToString(UUIDUtil.convertUUIDToBytes(userHandle));
        userCreateForm.setUserHandle(userHandleStr);
        model.addAttribute("userForm", userCreateForm);
        return VIEW_SIGNUP_SIGNUP;
    }

    @PostMapping(value = "/signup")
    public String create(HttpServletRequest request, @Valid @ModelAttribute("userForm") UserCreateForm userCreateForm, BindingResult result, Model model, RedirectAttributes redirectAttributes) {
        try {
            if (result.hasErrors()) {
                model.addAttribute("errorMessage", "Your input needs correction.");
                logger.debug("User input validation failed.");
                return VIEW_SIGNUP_SIGNUP;
            }

            WebAuthnRegistrationRequestValidationResponse registrationRequestValidationResponse;
            try {
                registrationRequestValidationResponse = registrationRequestValidator.validate(
                        request,
                        userCreateForm.getAuthenticator().getClientDataJSON(),
                        userCreateForm.getAuthenticator().getAttestationObject(),
                        userCreateForm.getAuthenticator().getTransports(),
                        userCreateForm.getAuthenticator().getClientExtensions()
                );
            } catch (WebAuthnException | WebAuthnAuthenticationException e) {
                model.addAttribute("errorMessage", "Authenticator registration request validation failed. Please try again.");
                logger.debug("WebAuthn registration request validation failed.", e);
                return VIEW_SIGNUP_SIGNUP;
            }

            String username = userCreateForm.getUsername();
            String password = passwordEncoder.encode(userCreateForm.getPassword());
            boolean singleFactorAuthenticationAllowed = userCreateForm.isSingleFactorAuthenticationAllowed();
            List<GrantedAuthority> authorities;
            if (singleFactorAuthenticationAllowed) {
                authorities = Collections.singletonList(new SimpleGrantedAuthority("SINGLE_FACTOR_AUTHN_ALLOWED"));
            } else {
                authorities = Collections.emptyList();
            }
            User user = new User(username, password, authorities);

            WebAuthnCredentialRecord authenticator = new WebAuthnCredentialRecordImpl(
                    "authenticator",
                    user.getUsername(),
                    registrationRequestValidationResponse.getAttestationObject().getAuthenticatorData().getAttestedCredentialData(),
                    registrationRequestValidationResponse.getAttestationObject().getAttestationStatement(),
                    registrationRequestValidationResponse.getAttestationObject().getAuthenticatorData().getSignCount(),
                    registrationRequestValidationResponse.getTransports(),
                    registrationRequestValidationResponse.getRegistrationExtensionsClientOutputs(),
                    registrationRequestValidationResponse.getAttestationObject().getAuthenticatorData().getExtensions()
            );

            try {
                userDetailsManager.createUser(user);
                webAuthnAuthenticatorManager.createCredentialRecord(authenticator);
            } catch (IllegalArgumentException ex) {
                model.addAttribute("errorMessage", "Registration failed. The user may already be registered.");
                logger.debug("Registration failed.", ex);
                return VIEW_SIGNUP_SIGNUP;
            }
        } catch (RuntimeException ex) {
            model.addAttribute("errorMessage", "Registration failed by unexpected error.");
            logger.debug("Registration failed.", ex);
            return VIEW_SIGNUP_SIGNUP;
        }

        redirectAttributes.addFlashAttribute("successMessage", "User registration finished.");
        return REDIRECT_LOGIN;
    }

    @GetMapping(value = "/login")
    public String login() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authenticationTrustResolver.isAnonymous(authentication)) {
            return VIEW_LOGIN_LOGIN;
        } else {
            return VIEW_LOGIN_AUTHENTICATOR_LOGIN;
        }
    }

    private List<String> getCredentialIds() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object principal = authentication.getPrincipal();
        if (principal == null || authenticationTrustResolver.isAnonymous(authentication)) {
            return Collections.emptyList();
        } else {
            try {
                List<WebAuthnCredentialRecord> webAuthnCredentialRecords = webAuthnAuthenticatorManager.loadCredentialRecordsByUserPrincipal(principal);
                return webAuthnCredentialRecords.stream()
                        .map(webAuthnAuthenticator -> Base64UrlUtil.encodeToString(webAuthnAuthenticator.getAttestedCredentialData().getCredentialId()))
                        .collect(Collectors.toList());
            } catch (PrincipalNotFoundException e) {
                return Collections.emptyList();
            }
        }
    }
}
