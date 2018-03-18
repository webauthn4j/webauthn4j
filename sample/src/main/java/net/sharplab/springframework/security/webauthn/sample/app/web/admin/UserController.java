package net.sharplab.springframework.security.webauthn.sample.app.web.admin;

import net.sharplab.springframework.security.webauthn.sample.app.web.UserHelper;
import net.sharplab.springframework.security.webauthn.sample.app.web.ViewNames;
import net.sharplab.springframework.security.webauthn.sample.domain.constant.MessageCodes;
import net.sharplab.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleBusinessException;
import net.sharplab.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleEntityNotFoundException;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import net.sharplab.springframework.security.webauthn.sample.domain.service.UserService;
import net.sharplab.springframework.security.webauthn.sample.domain.util.UUIDUtil;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
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

    private final ModelMapper modelMapper;

    private final UserService userService;
    private final UserHelper userHelper;

    @Autowired
    public UserController(ModelMapper modelMapper,
                          UserService userService,
                          UserHelper userHelper) {
        this.modelMapper = modelMapper;
        this.userService = userService;
        this.userHelper = userHelper;
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
        UserForm userForm = new UserForm();
        UUID userHandle = UUID.randomUUID();
        String userHandleStr = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(UUIDUtil.toByteArray(userHandle));
        userForm.setUserHandle(userHandleStr);
        model.addAttribute(userForm);
        return ViewNames.VIEW_USER_CREATE;
    }

    @RequestMapping(value = "/create", method = RequestMethod.POST)
    public String create(HttpServletRequest request, HttpServletResponse response, @Valid @ModelAttribute UserForm userForm,
                         BindingResult result, Model model, RedirectAttributes redirectAttributes) {

        if (result.hasErrors()) {
            return ViewNames.VIEW_USER_CREATE;
        }

        if (!userHelper.validateAuthenticators(model, request, response, userForm.getAuthenticators())){
            return ViewNames.VIEW_USER_CREATE;
        }

        User user = modelMapper.map(userForm, User.class);
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
        UserForm userForm = modelMapper.map(user, UserForm.class);
        model.addAttribute(userForm);
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
        UserForm userForm = modelMapper.map(user, UserForm.class);
        model.addAttribute(userForm);
        model.addAttribute(TARGET_USER_ID, userId);

        return ViewNames.VIEW_USER_PASSWORD_UPDATE;
    }

    @RequestMapping(value = "/{userId}", method = RequestMethod.POST)
    public String update(HttpServletRequest request, HttpServletResponse response, @PathVariable Integer userId, @Valid @ModelAttribute("userForm") UserUpdateForm userUpdateForm,
                         BindingResult result, Model model, RedirectAttributes redirectAttributes) {

        User user;
        try {
            user = userService.findOne(userId);
        }
        catch (WebAuthnSampleEntityNotFoundException ex){
            redirectAttributes.addFlashAttribute(ResultMessages.error().add(MessageCodes.Error.User.USER_NOT_FOUND));
            return ViewNames.REDIRECT_ADMIN_USERS;
        }

        if (result.hasErrors()) {
            model.addAttribute(TARGET_USER_ID, userId);
            UserForm userForm = modelMapper.map(user, UserForm.class);
            modelMapper.map(userUpdateForm, userForm);
            model.addAttribute(userForm);
            return ViewNames.VIEW_USER_UPDATE;
        }

        if (!userHelper.validateAuthenticators(model, request, response, userUpdateForm.getAuthenticators())){
            model.addAttribute(TARGET_USER_ID, userId);
            return ViewNames.VIEW_USER_UPDATE;
        }

        try {
            user = userService.findOne(userId);
            modelMapper.map(userUpdateForm, user);
            userService.update(user);
        } catch (WebAuthnSampleBusinessException ex) {
            UserForm userForm = modelMapper.map(user, UserForm.class);
            modelMapper.map(userUpdateForm, userForm);
            model.addAttribute(userForm);
            model.addAttribute(TARGET_USER_ID, userId);
            model.addAttribute(ex.getResultMessages());
            return ViewNames.VIEW_USER_UPDATE;
        }

        redirectAttributes.addFlashAttribute(ResultMessages.success().add(MessageCodes.Success.User.USER_UPDATED));
        return ViewNames.REDIRECT_ADMIN_USERS + user.getId();
    }

    @RequestMapping(value = "/updatePassword/{userId}", method = RequestMethod.POST)
    public String updatePassword(@PathVariable Integer userId, @Valid @ModelAttribute("userForm") UserPasswordForm userPasswordForm,
                         BindingResult result, Model model, RedirectAttributes redirectAttributes) {

        if (result.hasErrors()) {
            model.addAttribute(TARGET_USER_ID, userId);
            return ViewNames.VIEW_USER_PASSWORD_UPDATE;
        }

        User user;
        try {
            user = userService.findOne(userId);
            modelMapper.map(userPasswordForm, user);
            userService.update(user);
        } catch (WebAuthnSampleBusinessException ex) {
            model.addAttribute("userForm", userPasswordForm);
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
