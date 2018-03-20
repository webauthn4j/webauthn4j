package net.sharplab.springframework.security.webauthn.sample.app.util.validator;

import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Validation Annotation for ensuring property equality
 */
@Constraint(validatedBy = {EqualPropertiesValidator.class})
@Target({ElementType.TYPE, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface EqualProperties {

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    String property();

    String comparingProperty();

    String message() default "property {property} and {comparingProperty} mismatch";

    @interface List {
        EqualProperties[] value();
    }
}
