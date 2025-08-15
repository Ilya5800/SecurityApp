package ru.semin.springcourse.FirstSecurityApp.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import ru.semin.springcourse.FirstSecurityApp.services.PersonDetailsService;

import java.util.Collections;
import java.util.stream.Collectors;

@Component
public class AuthProviderImpl implements AuthenticationProvider {
private final PersonDetailsService personDetailsService;
    private  PasswordEncoder passwordEncoder;
    @Autowired
    public AuthProviderImpl(PersonDetailsService personDetailsService) {
        this.personDetailsService = personDetailsService;

    }


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        UserDetails personDetail = personDetailsService.loadUserByUsername(username);
        String password = authentication.getCredentials().toString();

        if(!password.equals(personDetail.getPassword())){
            throw new BadCredentialsException("Incorrect password");
        }
        return new UsernamePasswordAuthenticationToken(
                personDetail,
                personDetail.getPassword(),
                personDetail.getAuthorities()
        );
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return true;
    }
}
