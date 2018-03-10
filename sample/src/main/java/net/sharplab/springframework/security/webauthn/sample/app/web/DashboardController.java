package net.sharplab.springframework.security.webauthn.sample.app.web;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;


/**
 * Dashboard controller
 */
@SuppressWarnings("SameReturnValue")
@Controller
public class DashboardController {

    @RequestMapping(value = "/", method = RequestMethod.GET)
    public String index(Model model) {
        return "dashboard/index";
    }

}