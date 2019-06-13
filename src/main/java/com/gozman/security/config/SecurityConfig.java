package com.gozman.security.config;

import com.gozman.security.AuthentificationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.Array;
import java.util.Arrays;


@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthentificationProvider authentificationProvider;



    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated()
                .antMatchers("/login", "/login-error", "public", "/login2").permitAll()
                .antMatchers("/t1").hasRole("gozman");
               // .and()
               // .formLogin();

        UsernamePasswordAuthenticationFilter usernamePasswordAuthenticationFilter = new UsernamePasswordAuthenticationFilter();
        usernamePasswordAuthenticationFilter.setPostOnly(true);
        usernamePasswordAuthenticationFilter.setFilterProcessesUrl("/login2");


        /*
        * i commented the formLogin from above so I changed the authentification url to be a get for easy testing from the browser
         */
        usernamePasswordAuthenticationFilter.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/login2", "GET"));

        //by default only POST is supported
        usernamePasswordAuthenticationFilter.setPostOnly(false);


        /*
        * multiple authentification providers can be set
        * the order is important as the first one that is succesfull will define the user roles
        *
         */
        AuthenticationManager authenticationManager = new ProviderManager(Arrays.asList(authentificationProvider));
        usernamePasswordAuthenticationFilter.setAuthenticationManager(authenticationManager);


        /*
        * the native implementation of UsernamePasswordAuthentificationFilter gets the username and password values as
        * request params
        * if we wish to change this the most simple solution would be to extend UsernamePasswordAuthentificationFilter
        * and override the 'obtainUsername' and 'obtainPassword' fields
        *
         */
        usernamePasswordAuthenticationFilter.setUsernameParameter("username");
        usernamePasswordAuthenticationFilter.setPasswordParameter("password");

        /*
        * if we wish to  define our own behaviour for authentification succes we just implement the AuthenticationSuccessHandler
        * and register it
         */
       // usernamePasswordAuthenticationFilter.setAuthenticationSuccessHandler((request, response, authentication) -> { });

        /*
        * if we wish to define our own behaviour for authentification failure we just implement our own AuthenticationFailureHandler
        * and register it
         */
        //usernamePasswordAuthenticationFilter.setAuthenticationFailureHandler((request, response, exception) -> { });

       /*
       * add our own  custom AuthentificationFilter
        */
        http.addFilterAt(usernamePasswordAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

    }


    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authentificationProvider);
    }
}