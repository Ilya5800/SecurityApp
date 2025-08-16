package ru.semin.springcourse.FirstSecurityApp.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;
import ru.semin.springcourse.FirstSecurityApp.models.Person;
import ru.semin.springcourse.FirstSecurityApp.services.PersonDetailsService;
@Component
public class PersonValidator implements Validator {
    private final PersonDetailsService personDetailsService;
@Autowired
    public PersonValidator(PersonDetailsService personDetailsService) {
        this.personDetailsService = personDetailsService;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return Person.class.equals(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        Person person = (Person) target;

        try {
        personDetailsService.loadUserByUsername((person.getUsername()));
        }catch (UsernameNotFoundException ignore){
            return;
        }
        errors.rejectValue("username", "", "Человек с таким именем пользователя уже есть");
    }
}
