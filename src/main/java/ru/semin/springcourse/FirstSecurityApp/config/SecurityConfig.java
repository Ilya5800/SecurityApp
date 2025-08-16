package ru.semin.springcourse.FirstSecurityApp.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;



import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import ru.semin.springcourse.FirstSecurityApp.services.PersonDetailsService;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig  {
    private final PersonDetailsService personDetailsService;


    @Autowired
    public SecurityConfig( PersonDetailsService personDetailsService) {
        this.personDetailsService = personDetailsService;


    }



    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(personDetailsService);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

 @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

//        protected void configure(HttpSecurity httpSecurity) throws Exception {
//        httpSecurity.formLogin().loginPage("/auth/login")
//                .loginProcessingUrl("/process_login")
//                .defaultSuccessUrl("/hello",true).failureUrl("/auth/login?error");
//        }
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/login","/auth/registration","error").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(login -> login
                        .loginPage("/auth/login")
                        .loginProcessingUrl("/process_login")
                        .defaultSuccessUrl("/hello",true)
                        .failureUrl("/auth/login?error")
                ).logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/auth/login"));

        return http.build();
    }

}

