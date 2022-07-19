package io.security.basicsecurity;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;


@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;

    public SecurityConfig(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 유저 계정 생성
        // 패스워드는 암호화 할때 특정 알고리즘 방식이 사용됐는지 prefix로 적어야 한다. 그렇지 않으면 null 나옴 (ex. {noop})
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("USER","SYS");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN","SYS","USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /**
         * 기본적으로는 USER, ADMIN, SYS는 각각의 권한을 따로 가지고 있을 뿐이지 USER < ADMIN < SYS 와 같이 더 많은 권한을 가지고 있는 것이 아니다.
         *
         * - 그래서 role에 따로 각각 적어줘야함.
         * - 혹은 이후에 학습할 role hierarchy 설정을 해주면 ADMIN은 USER 권한을 가지고 있는 것이 가능해짐.
         */
        http
            .authorizeRequests()
            .antMatchers("/user").hasRole("USER")
            .antMatchers("/admin/pay").hasRole("ADMIN")
            .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
            .anyRequest().authenticated();

        http
            .formLogin()
        .and()
            .sessionManagement()
            .maximumSessions(1) // 최대 세션 갯수 1개
            .maxSessionsPreventsLogin(true); // 최대 세션 허용갯수 초과 시 인증 실패전략 사용
    }
}
