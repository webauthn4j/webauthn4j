package net.sharplab.springframework.security.webauthn.sample.app.web.admin;

import net.sharplab.springframework.security.webauthn.sample.app.web.helper.AuthenticatorHelper;
import net.sharplab.springframework.security.webauthn.sample.app.web.helper.UserHelper;
import net.sharplab.springframework.security.webauthn.sample.app.web.ViewNames;
import net.sharplab.springframework.security.webauthn.sample.app.web.validator.UserCreateFormValidator;
import net.sharplab.springframework.security.webauthn.sample.app.web.validator.UserUpdateFormValidator;
import net.sharplab.springframework.security.webauthn.sample.domain.constant.MessageCodes;
import net.sharplab.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleBusinessException;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import net.sharplab.springframework.security.webauthn.sample.domain.service.UserService;
import net.sharplab.springframework.security.webauthn.sample.util.UUIDUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.terasoluna.gfw.common.message.ResultMessages;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.util.UUID;

/**
 * Controller for user management
 */
@SuppressWarnings({"squid:S1166", "SameReturnValue"})
@RequestMapping(value = "/admin/users")
@Controller
public class UserController {

    private static final String TARGET_USER_ID = "targetUserId";

    @Autowired
    private UserCreateFormValidator userCreateFormValidator;

    @Autowired
    private UserUpdateFormValidator userUpdateFormValidator;

    @Autowired
    private UserService userService;

    @Autowired
    private UserHelper userHelper;

    @Autowired
    private AuthenticatorHelper authenticatorHelper;

    @InitBinder("userCreateForm")
    public void initUserCreateFormBinder(WebDataBinder webDataBinder){
        webDataBinder.addValidators(userCreateFormValidator);
    }

    @InitBinder("userUpdateForm")
    public void initUserUpdateFormBinder(WebDataBinder webDataBinder){
        webDataBinder.addValidators(userUpdateFormValidator);
    }

    @RequestMapping(value = "/", method = RequestMethod.GET)
    public String list(Pageable pageable, Model model, @RequestParam(required = false, value = "keyword") String keyword) {

        Page<User> page = userService.findAllByKeyword(pageable, keyword);
        model.addAttribute("page", page);
        model.addAttribute("users", page.getContent());

        return ViewNames.VIEW_USER_LIST;
    }

    @RequestMapping(value = "/create", method = RequestMethod.GET)
    public String template(Model model) {
        UserCreateForm userCreateForm = new UserCreateForm();
        UUID userHandle = UUID.randomUUID();
        String userHandleStr = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(UUIDUtil.toByteArray(userHandle));
        userCreateForm.setUserHandle(userHandleStr);
        model.addAttribute(userCreateForm);
        return ViewNames.VIEW_USER_CREATE;
    }

    @RequestMapping(value = "/create", method = RequestMethod.POST)
    public String create(HttpServletRequest request, HttpServletResponse response, @Valid @ModelAttribute UserCreateForm userCreateForm,
                         BindingResult result, Model model, RedirectAttributes redirectAttributes) {

        if (result.hasErrors()) {
            return ViewNames.VIEW_USER_CREATE;
        }

        if (!authenticatorHelper.validateAuthenticators(model, request, response, userCreateForm.getNewAuthenticators())) {
            return ViewNames.VIEW_USER_CREATE;
        }

        User user = userHelper.mapForCreate(userCreateForm);
        User createdUser;
        try {
            createdUser = userService.create(user);
        } catch (WebAuthnSampleBusinessException ex) {
            model.addAttribute(ex.getResultMessages());
            return ViewNames.VIEW_USER_CREATE;
        }

        redirectAttributes.addFlashAttribute(ResultMessages.success().add(MessageCodes.Success.User.USER_CREATED));
        return ViewNames.REDIRECT_ADMIN_USERS + createdUser.getId();
    }

    @RequestMapping(value = "/{userId}", method = RequestMethod.GET)
    public String show(Model model, RedirectAttributes redirectAttributes, @PathVariable Integer userId) {

        User user;
        try {
            user = userService.findOne(userId);
        } catch (WebAuthnSampleBusinessException ex) {
            redirectAttributes.addFlashAttribute(ex.getResultMessages());
            return ViewNames.REDIRECT_ADMIN_USERS;
        }
        UserUpdateForm userUpdateForm = userHelper.map(user, (UserUpdateForm) null);
        model.addAttribute(userUpdateForm);
        model.addAttribute(TARGET_USER_ID, userId);

        return ViewNames.VIEW_USER_UPDATE;
    }

    @RequestMapping(value = "/updatePassword/{userId}", method = RequestMethod.GET)
    public String showPasswordUpdateView(Model model, RedirectAttributes redirectAttributes, @PathVariable Integer userId) {

        User user;
        try {
            user = userService.findOne(userId);
        } catch (WebAuthnSampleBusinessException ex) {
            redirectAttributes.addFlashAttribute(ex.getResultMessages());
            return ViewNames.REDIRECT_ADMIN_USERS;
        }
        UserPasswordForm userPasswordForm = userHelper.map(user, (UserPasswordForm) null);
        model.addAttribute(userPasswordForm);
        model.addAttribute(TARGET_USER_ID, userId);

        return ViewNames.VIEW_USER_PASSWORD_UPDATE;
    }

    @RequestMapping(value = "/{userId}", method = RequestMethod.POST)
    public String update(HttpServletRequest request, HttpServletResponse response, @PathVariable Integer userId, @Valid @ModelAttribute UserUpdateForm userUpdateForm,
                         BindingResult result, Model model, RedirectAttributes redirectAttributes) {

        if (result.hasErrors()) {
            model.addAttribute(TARGET_USER_ID, userId);
            return ViewNames.VIEW_USER_UPDATE;
        }

        if (!authenticatorHelper.validateAuthenticators(model, request, response, userUpdateForm.getNewAuthenticators())) {
            model.addAttribute(TARGET_USER_ID, userId);
            return ViewNames.VIEW_USER_UPDATE;
        }

        User user;

        try {
            user = userService.findOne(userId);
            userHelper.mapForUpdate(userUpdateForm, user);
            userService.update(user);
        } catch (WebAuthnSampleBusinessException ex) {
            model.addAttribute(TARGET_USER_ID, userId);
            model.addAttribute(ex.getResultMessages());
            return ViewNames.VIEW_USER_UPDATE;
        }

        redirectAttributes.addFlashAttribute(ResultMessages.success().add(MessageCodes.Success.User.USER_UPDATED));
        return ViewNames.REDIRECT_ADMIN_USERS + user.getId();
    }

    @RequestMapping(value = "/updatePassword/{userId}", method = RequestMethod.POST)
    public String updatePassword(@PathVariable Integer userId, @Valid @ModelAttribute UserPasswordForm userPasswordForm,
                                 BindingResult result, Model model, RedirectAttributes redirectAttributes) {

        if (result.hasErrors()) {
            model.addAttribute(TARGET_USER_ID, userId);
            return ViewNames.VIEW_USER_PASSWORD_UPDATE;
        }

        User user;
        try {
            user = userService.findOne(userId);
            userHelper.mapForUpdate(userPasswordForm, user);
            userService.update(user);
        } catch (WebAuthnSampleBusinessException ex) {
            model.addAttribute(userPasswordForm);
            model.addAttribute(TARGET_USER_ID, userId);
            model.addAttribute(ex.getResultMessages());
            return ViewNames.VIEW_USER_PASSWORD_UPDATE;
        }

        redirectAttributes.addFlashAttribute(ResultMessages.success().add(MessageCodes.Success.User.USER_PASSWORD_UPDATED));
        return ViewNames.REDIRECT_ADMIN_USERS_UPDATE_PASSWORD + user.getId();
    }

    @RequestMapping(value = "/delete/{userId}", method = RequestMethod.POST)
    public String delete(RedirectAttributes redirectAttributes, Model model, @PathVariable Integer userId) {

        try {
            userService.delete(userId);
        } catch (WebAuthnSampleBusinessException ex) {
            redirectAttributes.addFlashAttribute(ex.getResultMessages());
            return ViewNames.REDIRECT_ADMIN_USERS;
        }

        redirectAttributes.addFlashAttribute(ResultMessages.success().add(MessageCodes.Success.User.USER_DELETED));
        return ViewNames.REDIRECT_ADMIN_USERS;
    }


}
