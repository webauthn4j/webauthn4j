package net.sharplab.springframework.security.webauthn.sample.app.web;

/**
 * View Name Constants
 */
@SuppressWarnings("squid:S2068")
public class ViewNames {

    public static final String REDIRECT_LOGIN = "redirect:/login/";

    public static final String VIEW_SIGNUP_SIGNUP = "signup/signup";

    public static final String REDIRECT_DASHBOARD = "redirect:/";

    public static final String VIEW_PROFILE_PASSWORD_UPDATE = "profile/passwordUpdate";
    public static final String REDIRECT_PROFILE_UPDATE_PASSWORD = "redirect:/profile/updatePassword/";

    public static final String VIEW_USER_CREATE = "user/create";
    public static final String VIEW_USER_UPDATE = "user/update";
    public static final String VIEW_USER_PASSWORD_UPDATE = "user/passwordUpdate";
    public static final String VIEW_USER_LIST = "user/list";
    public static final String REDIRECT_ADMIN_USERS = "redirect:/admin/users/";
    public static final String REDIRECT_ADMIN_USERS_UPDATE_PASSWORD = "redirect:/admin/users/updatePassword/";

    public static final String VIEW_GROUP_CREATE = "group/create";
    public static final String VIEW_GROUP_UPDATE = "group/update";
    public static final String VIEW_GROUP_LIST = "group/list";
    public static final String REDIRECT_ADMIN_GROUPS = "redirect:/admin/groups/";

    public static final String VIEW_AUTHORITY_CREATE = "authority/create";
    public static final String VIEW_AUTHORITY_UPDATE = "authority/update";
    public static final String VIEW_AUTHORITY_LIST = "authority/list";
    public static final String REDIRECT_ADMIN_AUTHORITIES = "redirect:/admin/authorities/";

    public static final String VIEW_PROFILE_UPDATE = "profile/update";
    public static final String REDIRECT_PROFILE = "redirect:/profile/";

    public static final String VIEW_LOGIN_LOGIN = "login/login";
    public static final String VIEW_LOGIN_AUTHENTICATOR_LOGIN = "login/authenticatorLogin";

    private ViewNames(){}


}
