package net.sharplab.springframework.security.webauthn.sample.app.web;

import net.sharplab.springframework.security.webauthn.sample.app.web.admin.UserForm;
import net.sharplab.springframework.security.webauthn.sample.domain.constant.MessageCodes;
import net.sharplab.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleBusinessException;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import net.sharplab.springframework.security.webauthn.sample.domain.service.UserService;
import net.sharplab.springframework.security.webauthn.sample.domain.util.UUIDUtil;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.Base64Utils;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.terasoluna.gfw.common.message.ResultMessages;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.util.UUID;

@RequestMapping(value = "/")
@Controller
public class SignupController {

    private final ModelMapper modelMapper;

    private final UserService userService;
    private UserHelper userHelper;

    @Autowired
    public SignupController(ModelMapper modelMapper,
                          UserService userService,
                          UserHelper userHelper) {
        this.modelMapper = modelMapper;
        this.userService = userService;
        this.userHelper = userHelper;
    }


    @RequestMapping(value = "/signup", method = RequestMethod.GET)
    public String template(Model model) {
        UserForm userForm = new UserForm();
        UUID userHandle = UUID.randomUUID();
        String userHandleStr = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(UUIDUtil.toByteArray(userHandle));
        userForm.setUserHandle(userHandleStr);
        model.addAttribute(userForm);
        return ViewNames.VIEW_SIGNUP_SIGNUP;
    }

    @RequestMapping(value = "/signup", method = RequestMethod.POST)
    public String create(HttpServletRequest request, HttpServletResponse response, @Valid @ModelAttribute UserForm userForm,
                         BindingResult result, Model model, RedirectAttributes redirectAttributes) {

    if (result.hasErrors()) {
            model.addAttribute(userForm);
        return ViewNames.VIEW_SIGNUP_SIGNUP;
    }

    if (!userHelper.validateAuthenticators(model, request, response, userForm.getAuthenticators())){
        model.addAttribute(userForm);
        return ViewNames.VIEW_SIGNUP_SIGNUP;
    }

    User user = modelMapper.map(userForm, User.class);
        try {
        userService.create(user);
    } catch (WebAuthnSampleBusinessException ex) {
        model.addAttribute(ex.getResultMessages());
        return ViewNames.VIEW_SIGNUP_SIGNUP;
    }
        redirectAttributes.addFlashAttribute(ResultMessages.success().add(MessageCodes.Success.User.USER_CREATED));

        return ViewNames.REDIRECT_LOGIN;
    }

}
