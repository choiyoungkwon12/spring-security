package io.security.corespringsecurity.security.configs;

import javax.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final AuthenticationProvider authenticationProvider;
    private final AuthenticationSuccessHandler customAuthenticationSuccessHandler;
    private final AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource;

    public SecurityConfig(AuthenticationProvider authenticationProvider,
            AuthenticationDetailsSource < HttpServletRequest, WebAuthenticationDetails > authenticationDetailsSource,
            AuthenticationSuccessHandler customAuthenticationSuccessHandler) {
            this.authenticationProvider = authenticationProvider;
            this.customAuthenticationSuccessHandler = customAuthenticationSuccessHandler;
            this.authenticationDetailsSource = authenticationDetailsSource;

        }

        @Override
        protected void configure (AuthenticationManagerBuilder auth) throws Exception {
            auth.authenticationProvider(authenticationProvider);
        }

        @Override
        protected void configure (final HttpSecurity http) throws Exception {
            http
                .authorizeRequests()
                .antMatchers("/", "/users").permitAll()
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated()

                .and()

                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .authenticationDetailsSource(authenticationDetailsSource)
                .successHandler(customAuthenticationSuccessHandler)
                .defaultSuccessUrl("/")
                .permitAll();
        }

        @Override
        public void configure (WebSecurity web) throws Exception {
            web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
        }
    }
