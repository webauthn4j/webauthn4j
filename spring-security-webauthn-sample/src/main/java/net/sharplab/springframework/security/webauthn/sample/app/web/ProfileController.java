package net.sharplab.springframework.security.webauthn.sample.app.web;

import net.sharplab.springframework.security.webauthn.sample.app.web.helper.AuthenticatorHelper;
import net.sharplab.springframework.security.webauthn.sample.app.web.helper.ProfileHelper;
import net.sharplab.springframework.security.webauthn.sample.app.web.validator.ProfileFormValidator;
import net.sharplab.springframework.security.webauthn.sample.domain.constant.MessageCodes;
import net.sharplab.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleBusinessException;
import net.sharplab.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleEntityNotFoundException;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import net.sharplab.springframework.security.webauthn.sample.domain.service.ProfileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.terasoluna.gfw.common.message.ResultMessages;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

/**
 * Profile controller for managing login user
 */
@SuppressWarnings({"squid:S1166", "SameReturnValue"})
@Controller
@RequestMapping(value = "/profile")
public class ProfileController {

    private static final String TARGET_USER_ID = "targetUserId";

    private final ProfileService profileService;

    @Autowired
    private ProfileFormValidator profileFormValidator;

    @Autowired
    private ProfileHelper profileHelper;

    @Autowired
    private AuthenticatorHelper authenticatorHelper;

    @InitBinder("profileForm")
    public void initBinder(WebDataBinder webDataBinder){
        webDataBinder.addValidators(profileFormValidator);
    }

    @Autowired
    public ProfileController(ProfileService profileService) {
        this.profileService = profileService;
    }

    @RequestMapping(value = "/", method = RequestMethod.GET)
    public String show(@AuthenticationPrincipal User loginUser, Model model, RedirectAttributes redirectAttributes) {
        try {
            User user = profileService.findOne(loginUser.getId());
            ProfileForm profileForm = profileHelper.map(user, (ProfileForm) null);
            model.addAttribute(profileForm);
            return ViewNames.VIEW_PROFILE_UPDATE;
        }
        catch (WebAuthnSampleEntityNotFoundException ex) {
            redirectAttributes.addFlashAttribute(ex.getResultMessages());
            return ViewNames.REDIRECT_DASHBOARD;
        }
    }

    @RequestMapping(value = "/updatePassword", method = RequestMethod.GET)
    public String showPasswordUpdateView(@AuthenticationPrincipal User loginUser, Model model, RedirectAttributes redirectAttributes) {
        int userId = loginUser.getId();
        User user;
        try {
            user = profileService.findOne(userId);
            ProfilePasswordForm profilePasswordForm = profileHelper.map(user, (ProfilePasswordForm) null);
            model.addAttribute(profilePasswordForm);
            return ViewNames.VIEW_PROFILE_PASSWORD_UPDATE;
        }
        catch (WebAuthnSampleBusinessException ex) {
            redirectAttributes.addFlashAttribute(ex.getResultMessages());
            return ViewNames.REDIRECT_DASHBOARD;
        }
    }

    @RequestMapping(value = "/", method = RequestMethod.POST)
    public String update(HttpServletRequest request, HttpServletResponse response,
                         @AuthenticationPrincipal User loginUser, @Valid @ModelAttribute ProfileForm profileForm,
                         BindingResult result, Model model, RedirectAttributes redirectAttributes) {
        if (result.hasErrors()) {
            return ViewNames.VIEW_PROFILE_UPDATE;
        }

        if (!authenticatorHelper.validateAuthenticators(model, request, response, profileForm.getNewAuthenticators())) {
            return ViewNames.VIEW_USER_CREATE;
        }

        int userId = loginUser.getId();

        try {
            User user = profileService.findOne(userId);
            profileHelper.mapForUpdate(profileForm, user);
            profileService.update(user);
        }
        catch (WebAuthnSampleEntityNotFoundException ex) {
            model.addAttribute(ex.getResultMessages());
            return ViewNames.REDIRECT_DASHBOARD;
        }
        catch (WebAuthnSampleBusinessException ex) {
            model.addAttribute(ex.getResultMessages());
            return ViewNames.VIEW_PROFILE_UPDATE;
        }

        redirectAttributes.addFlashAttribute(ResultMessages.success().add(MessageCodes.Success.Profile.PROFILE_UPDATED));
        return ViewNames.REDIRECT_PROFILE;
    }

    @RequestMapping(value = "/updatePassword", method = RequestMethod.POST)
    public String updatePassword(@AuthenticationPrincipal User loginUser, @Valid @ModelAttribute ProfilePasswordForm profileForm,
                                 BindingResult result, Model model, RedirectAttributes redirectAttributes) {

        int userId = loginUser.getId();

        if (result.hasErrors()) {
            model.addAttribute(TARGET_USER_ID, userId);
            return ViewNames.VIEW_PROFILE_PASSWORD_UPDATE;
        }

        User user;
        try {
            user = profileService.findOne(userId);
            profileHelper.mapForUpdate(profileForm, user);
            profileService.update(user);
        } catch (WebAuthnSampleBusinessException ex) {
            model.addAttribute(TARGET_USER_ID, userId);
            model.addAttribute(ex.getResultMessages());
            return ViewNames.VIEW_PROFILE_PASSWORD_UPDATE;
        }

        redirectAttributes.addFlashAttribute(ResultMessages.success().add(MessageCodes.Success.User.USER_PASSWORD_UPDATED));
        return ViewNames.REDIRECT_PROFILE_UPDATE_PASSWORD;
    }

}
