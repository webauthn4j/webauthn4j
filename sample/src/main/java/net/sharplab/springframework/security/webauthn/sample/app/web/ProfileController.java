package net.sharplab.springframework.security.webauthn.sample.app.web;

import net.sharplab.springframework.security.webauthn.sample.domain.constant.MessageCodes;
import net.sharplab.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleBusinessException;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import net.sharplab.springframework.security.webauthn.sample.domain.service.ProfileService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.terasoluna.gfw.common.exception.BusinessException;
import org.terasoluna.gfw.common.message.ResultMessages;

import javax.validation.Valid;

/**
 * Profile controller for managing login user
 */
@SuppressWarnings({"squid:S1166", "SameReturnValue"})
@Controller
@RequestMapping(value = "/profile")
public class ProfileController {

    private static final String TARGET_USER_ID = "targetUserId";

    private final ModelMapper modelMapper;

    private final ProfileService profileService;

    @Autowired
    public ProfileController(ModelMapper modelMapper, ProfileService profileService) {
        this.modelMapper = modelMapper;
        this.profileService = profileService;
    }

    @RequestMapping(value = "/", method = RequestMethod.GET)
    public String show(@AuthenticationPrincipal User loginUser, Model model) {
        User user = profileService.findOne(loginUser.getId());
        ProfileUpdateForm profileUpdateForm = modelMapper.map(user, ProfileUpdateForm.class);
        model.addAttribute("profileForm", profileUpdateForm);

        return ViewNames.VIEW_PROFILE_UPDATE;
    }

    @RequestMapping(value = "/updatePassword", method = RequestMethod.GET)
    public String showPasswordUpdateView(@AuthenticationPrincipal User loginUser, Model model, RedirectAttributes redirectAttributes) {

        int userId = loginUser.getId();
        User user;
        try {
            user = profileService.findOne(userId);
        } catch (WebAuthnSampleBusinessException ex) {
            redirectAttributes.addFlashAttribute(ex.getResultMessages());
            return ViewNames.REDIRECT_DASHBOARD;
        }
        ProfilePasswordForm profilePasswordForm = modelMapper.map(user, ProfilePasswordForm.class);
        model.addAttribute("profileForm", profilePasswordForm);

        return ViewNames.VIEW_PROFILE_PASSWORD_UPDATE;
    }

    @RequestMapping(value = "/", method = RequestMethod.POST)
    public String update(@AuthenticationPrincipal User loginUser, @Valid @ModelAttribute("profileForm") ProfileUpdateForm profileUpdateForm,
                         BindingResult result, Model model, RedirectAttributes redirectAttributes){
        if(result.hasErrors()){
            return ViewNames.VIEW_PROFILE_UPDATE;
        }

        int userId = loginUser.getId();
        try{
            User user = profileService.findOne(userId);
            modelMapper.map(profileUpdateForm, user);
            profileService.update(user);
        }
        catch(BusinessException ex){
            model.addAttribute(ex.getResultMessages());
            return ViewNames.VIEW_PROFILE_UPDATE;
        }

        redirectAttributes.addFlashAttribute(ResultMessages.success().add(MessageCodes.Success.Profile.PROFILE_UPDATED));
        return ViewNames.REDIRECT_PROFILE;
    }

    @RequestMapping(value = "/updatePassword", method = RequestMethod.POST)
    public String updatePassword(@AuthenticationPrincipal User loginUser, @Valid @ModelAttribute("profileForm") ProfilePasswordForm profileForm,
                                 BindingResult result, Model model, RedirectAttributes redirectAttributes) {

        int userId = loginUser.getId();

        if (result.hasErrors()) {
            model.addAttribute(TARGET_USER_ID, userId);
            return ViewNames.VIEW_PROFILE_PASSWORD_UPDATE;
        }

        User user;
        try {
            user = profileService.findOne(userId);
            modelMapper.map(profileForm, user);
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
