package net.sharplab.springframework.security.webauthn.sample.app.web.admin;

import net.sharplab.springframework.security.webauthn.sample.domain.constant.MessageCodes;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.terasoluna.gfw.common.exception.BusinessException;
import org.terasoluna.gfw.common.exception.SystemException;
import org.terasoluna.gfw.common.message.ResultMessages;

/**
 * Controller for error handling
 */
@Controller
public class ErrorController {

    @RequestMapping("/error/500")
    public String show500(){
        return "error/500";
    }

    @RequestMapping("/error/404")
    public String show404(){
        return "error/404";
    }

    @RequestMapping({"/error/403", "/error/accessDeniedError"})
    public String show403(){
        return "error/403";
    }

    /**
     * Throws business exception to simulate an unhandled business exception.
     */
    @RequestMapping("/admin/error/throwBusinessException")
    public void throwBusinessError(){
        throw new BusinessException(ResultMessages.error().add(MessageCodes.Error.UNKNOWN));
    }

    /**
     * Throws business exception to simulate an unhandled business exception.
     */
    @RequestMapping("/admin/error/throwSystemException")
    public void throwSystemError(){
        throw new SystemException(MessageCodes.Error.UNKNOWN, "exception message");
    }

}
