package net.sharplab.springframework.security.webauthn.sample.app.test;

import org.springframework.security.test.context.support.WithSecurityContext;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * Annotation for instructing to use User's Mock
 */
@Retention(RetentionPolicy.RUNTIME)
@WithSecurityContext(factory = WithMockUserSecurityContextFactory.class)
public @interface WithMockUser {

    int id() default 0;
    String  userHandleString() default "";
    String  firstName() default "";
    String  lastName() default "";
    String  emailAddress() default "";

    String[] authorities() default {};
    String[] groups() default {};
    String[] authenticators() default {};

    boolean locked() default false;
    boolean passwordAuthenticationAllowed() default false;

}
