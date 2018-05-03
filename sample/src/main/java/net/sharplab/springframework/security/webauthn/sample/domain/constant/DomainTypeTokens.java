package net.sharplab.springframework.security.webauthn.sample.domain.constant;

import net.sharplab.springframework.security.webauthn.sample.domain.entity.AuthenticatorEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.AuthorityEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.GroupEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.model.Authenticator;
import net.sharplab.springframework.security.webauthn.sample.domain.model.Authority;
import net.sharplab.springframework.security.webauthn.sample.domain.model.Group;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import org.modelmapper.TypeToken;
import org.springframework.data.domain.PageImpl;

import java.lang.reflect.Type;
import java.util.ArrayList;

/**
 * ModelMapper TypeToken constants
 */
public class DomainTypeTokens {

    public static final Type UserList = new TypeToken<ArrayList<User>>() {
    }.getType();
    public static final Type GroupList = new TypeToken<ArrayList<Group>>() {
    }.getType();
    public static final Type AuthorityList = new TypeToken<ArrayList<Authority>>() {
    }.getType();
    public static final Type AuthenticatorList = new TypeToken<ArrayList<Authenticator>>() {
    }.getType();

    public static final Type GroupEntityList = new TypeToken<ArrayList<GroupEntity>>() {
    }.getType();
    public static final Type AuthorityEntityList = new TypeToken<ArrayList<AuthorityEntity>>() {
    }.getType();
    public static final Type AuthenticatorEntityList = new TypeToken<ArrayList<AuthenticatorEntity>>() {
    }.getType();

    public static final Type UserPage = new TypeToken<PageImpl<User>>() {
    }.getType();
    public static final Type GroupPage = new TypeToken<PageImpl<Group>>() {
    }.getType();
    public static final Type AuthorityPage = new TypeToken<PageImpl<Authority>>() {
    }.getType();

    private DomainTypeTokens() {
    }
}
