package net.sharplab.springframework.security.webauthn.sample.app.web;

import org.springframework.security.authentication.FirstOfMultiFactorAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * Login controller
 */
@SuppressWarnings("SameReturnValue")
@Controller
public class LoginController {


    /**
     * ログインページ
     *
     * @return 論理ビュー名
     */
    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public String login() {
        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof FirstOfMultiFactorAuthenticationToken) {
            return ViewNames.VIEW_LOGIN_AUTHENTICATOR_LOGIN;
        } else {
            return ViewNames.VIEW_LOGIN_LOGIN;
        }
    }
}
