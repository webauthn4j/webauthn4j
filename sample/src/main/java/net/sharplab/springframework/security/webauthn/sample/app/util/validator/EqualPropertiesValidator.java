package net.sharplab.springframework.security.webauthn.sample.app.util.validator;

import org.springframework.beans.BeanWrapper;
import org.springframework.beans.BeanWrapperImpl;
import org.springframework.util.ObjectUtils;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

/**
 * Property equality validator
 */
@SuppressWarnings("WeakerAccess")
public class EqualPropertiesValidator implements ConstraintValidator<EqualProperties, Object> {

    private String property;
    private String comparingProperty;
    private String message;

    @Override
    public void initialize(EqualProperties constraintAnnotation) {
        this.property = constraintAnnotation.property();
        this.comparingProperty = constraintAnnotation.comparingProperty();
        this.message = constraintAnnotation.message();
    }

    @Override
    public boolean isValid(Object value, ConstraintValidatorContext context) {
        BeanWrapper beanWrapper = new BeanWrapperImpl(value);
        Object propertyValue = beanWrapper.getPropertyValue(property);
        Object comparingPropertyValue = beanWrapper.getPropertyValue(comparingProperty);
        if (ObjectUtils.nullSafeEquals(propertyValue, comparingPropertyValue)) {
            return true;
        } else {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(message)
                    .addPropertyNode(property).addConstraintViolation();
            return false;
        }
    }

}
