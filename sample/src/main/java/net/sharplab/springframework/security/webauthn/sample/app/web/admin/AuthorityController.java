package net.sharplab.springframework.security.webauthn.sample.app.web.admin;

import net.sharplab.springframework.security.webauthn.sample.app.web.ViewNames;
import net.sharplab.springframework.security.webauthn.sample.domain.constant.MessageCodes;
import net.sharplab.springframework.security.webauthn.sample.domain.dto.AuthorityUpdateDto;
import net.sharplab.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleEntityNotFoundException;
import net.sharplab.springframework.security.webauthn.sample.domain.model.Authority;
import net.sharplab.springframework.security.webauthn.sample.domain.service.AuthorityService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.terasoluna.gfw.common.exception.BusinessException;
import org.terasoluna.gfw.common.message.ResultMessages;

import javax.validation.Valid;

/**
 * Controller for authority management
 */
@SuppressWarnings({"squid:S1166", "SameReturnValue"})
@RequestMapping(value="/admin/authorities")
@Controller
public class AuthorityController {

    private final ModelMapper modelMapper;

    private final AuthorityService authorityService;

    @Autowired
    public AuthorityController(ModelMapper modelMapper, AuthorityService authorityService) {
        this.modelMapper = modelMapper;
        this.authorityService = authorityService;
    }

    @RequestMapping(value = "/", method = RequestMethod.GET)
    public String list(Pageable pageable, Model model, @RequestParam(required = false, value = "keyword") String keyword) {

        Page<Authority> page = authorityService.findAllByKeyword(pageable, keyword);
        model.addAttribute("page", page);
        model.addAttribute("authorities", page.getContent());

        return ViewNames.VIEW_AUTHORITY_LIST;
    }

    @RequestMapping(value = "/{authorityId}", method = RequestMethod.GET)
    public String show(Model model, RedirectAttributes redirectAttributes, @PathVariable Integer authorityId) {

        Authority authority;
        try {
            authority = authorityService.findOne(authorityId);
        } catch (BusinessException ex) {
            redirectAttributes.addFlashAttribute(ex.getResultMessages());
            return ViewNames.REDIRECT_ADMIN_AUTHORITIES;
        }
        AuthorityDto authorityDto = modelMapper.map(authority, AuthorityDto.class);
        return respondAuthorityUpdateView(model, authorityDto, authorityId);
    }

    @RequestMapping(value = "/{authorityId}", method = RequestMethod.POST)
    public String update(@PathVariable Integer authorityId, @Valid @ModelAttribute AuthorityForm authorityForm, BindingResult result, Model model, RedirectAttributes redirectAttributes) {

        //入力チェック
        if(authorityId == null){
            redirectAttributes.addFlashAttribute(MessageCodes.Error.Authority.AUTHORITY_NOT_FOUND);
            return ViewNames.REDIRECT_ADMIN_AUTHORITIES;
        }
        if (result.hasErrors()) {
            Authority authority = authorityService.findOne(authorityId);
            AuthorityDto authorityDto = modelMapper.map(authority, AuthorityDto.class);
            modelMapper.map(authorityForm, authorityDto);
            return respondAuthorityUpdateView(model, authorityDto, authorityId);
        }

        //処理
        try {
            AuthorityUpdateDto authorityUpdateDto = modelMapper.map(authorityForm, AuthorityUpdateDto.class);
            authorityUpdateDto.setId(authorityId);
            authorityService.update(authorityUpdateDto);
        }
        catch (WebAuthnSampleEntityNotFoundException ex){
            redirectAttributes.addFlashAttribute(MessageCodes.Error.Authority.AUTHORITY_NOT_FOUND);
            return ViewNames.REDIRECT_ADMIN_AUTHORITIES;
        }
        catch (BusinessException ex) {
            Authority authority = authorityService.findOne(authorityId);
            AuthorityDto authorityDto = modelMapper.map(authority, AuthorityDto.class);
            model.addAttribute(ex.getResultMessages());
            return respondAuthorityUpdateView(model, authorityDto, authorityId);
        }

        redirectAttributes.addFlashAttribute(ResultMessages.success().add(MessageCodes.Success.Authority.AUTHORITY_UPDATED));
        return ViewNames.REDIRECT_ADMIN_AUTHORITIES + authorityId;
    }

    private String respondAuthorityUpdateView(Model model, AuthorityDto authorityDto, int authorityId){
        model.addAttribute(authorityDto);
        model.addAttribute("targetAuthorityId", authorityId);
        return ViewNames.VIEW_AUTHORITY_UPDATE;
    }

}
