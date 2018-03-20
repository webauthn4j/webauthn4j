package net.sharplab.springframework.security.webauthn.sample.app.web.admin;

import net.sharplab.springframework.security.webauthn.sample.app.web.ViewNames;
import net.sharplab.springframework.security.webauthn.sample.domain.constant.MessageCodes;
import net.sharplab.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleBusinessException;
import net.sharplab.springframework.security.webauthn.sample.domain.model.Group;
import net.sharplab.springframework.security.webauthn.sample.domain.service.GroupService;
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

import javax.validation.Valid;

/**
 * Controller for group management
 */
@SuppressWarnings({"squid:S1166", "SameReturnValue"})
@RequestMapping(value = "/admin/groups")
@Controller
public class GroupController {

    private static final String TARGET_GROUP_ID = "targetGroupId";

    private final ModelMapper modelMapper;

    private final GroupService groupService;

    @Autowired
    public GroupController(ModelMapper modelMapper, GroupService groupService) {
        this.modelMapper = modelMapper;
        this.groupService = groupService;
    }

    @RequestMapping(value = "/", method = RequestMethod.GET)
    public String list(Pageable pageable, Model model, @RequestParam(required = false, value = "keyword") String keyword) {

        Page<Group> page = groupService.findAllByKeyword(pageable, keyword);
        model.addAttribute("page", page);
        model.addAttribute("groups", page.getContent());

        return ViewNames.VIEW_GROUP_LIST;
    }


    @RequestMapping(value = "/create", method = RequestMethod.GET)
    public String template(Model model) {
        GroupForm groupForm = new GroupForm();
        model.addAttribute(groupForm);
        return ViewNames.VIEW_GROUP_CREATE;
    }

    @RequestMapping(value = "/create", method = RequestMethod.POST)
    public String create(@Valid @ModelAttribute GroupForm groupForm, BindingResult result, Model model, RedirectAttributes redirectAttributes) {

        if (result.hasErrors()) {
            model.addAttribute(groupForm);
            return ViewNames.VIEW_GROUP_CREATE;
        }
        Group group = modelMapper.map(groupForm, Group.class);
        Group createdGroup;
        try {
            createdGroup = groupService.create(group);
        } catch (WebAuthnSampleBusinessException ex) {
            model.addAttribute(ex.getResultMessages());
            return ViewNames.VIEW_GROUP_CREATE;
        }
        redirectAttributes.addFlashAttribute(ResultMessages.success().add(MessageCodes.Success.Group.GROUP_CREATED));

        return ViewNames.REDIRECT_ADMIN_GROUPS + createdGroup.getId();
    }


    @RequestMapping(value = "/{groupId}", method = RequestMethod.GET)
    public String show(Model model, RedirectAttributes redirectAttributes, @PathVariable Integer groupId) {

        Group group;
        try {
            group = groupService.findOne(groupId);
        } catch (WebAuthnSampleBusinessException ex) {
            redirectAttributes.addFlashAttribute(ex.getResultMessages());
            return ViewNames.REDIRECT_ADMIN_GROUPS;
        }
        GroupForm groupForm = modelMapper.map(group, GroupForm.class);
        model.addAttribute(groupForm);
        model.addAttribute(TARGET_GROUP_ID, groupId);

        return ViewNames.VIEW_GROUP_UPDATE;
    }

    @RequestMapping(value = "/{groupId}", method = RequestMethod.POST)
    public String update(@PathVariable Integer groupId, @Valid @ModelAttribute GroupForm groupForm, BindingResult result, Model model, RedirectAttributes redirectAttributes) {

        if (result.hasErrors()) {
            model.addAttribute(groupForm);
            model.addAttribute(TARGET_GROUP_ID, groupId);
            return ViewNames.VIEW_GROUP_UPDATE;
        }

        Group group = modelMapper.map(groupForm, Group.class);
        group.setId(groupId);
        try {
            groupService.update(group);
        } catch (WebAuthnSampleBusinessException ex) {
            model.addAttribute(groupForm);
            model.addAttribute(TARGET_GROUP_ID, groupId);
            model.addAttribute(ex.getResultMessages());
            return ViewNames.VIEW_GROUP_UPDATE;
        }

        redirectAttributes.addFlashAttribute(ResultMessages.success().add(MessageCodes.Success.Group.GROUP_UPDATED));
        return ViewNames.REDIRECT_ADMIN_GROUPS + group.getId();
    }

    @RequestMapping(value = "/delete/{groupId}", method = RequestMethod.POST)
    public String delete(RedirectAttributes redirectAttributes, Model model, @PathVariable Integer groupId) {

        if (groupId == null) {
            redirectAttributes.addFlashAttribute(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND));
            return ViewNames.REDIRECT_ADMIN_GROUPS;
        }
        try {
            groupService.delete(groupId);
        } catch (WebAuthnSampleBusinessException ex) {
            redirectAttributes.addFlashAttribute(ex.getResultMessages());
            return ViewNames.REDIRECT_ADMIN_GROUPS;
        }

        redirectAttributes.addFlashAttribute(ResultMessages.success().add(MessageCodes.Success.Group.GROUP_DELETED));
        return ViewNames.REDIRECT_ADMIN_GROUPS;
    }


}
