package com.zubaray.market.web.security;

import com.zubaray.market.domain.service.DzUsersDetailService;
import com.zubaray.market.web.security.filter.JwtFilterRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private DzUsersDetailService dzUsersDetailService;

    @Autowired
    private JwtFilterRequest jwtFilterRequest;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(dzUsersDetailService);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
       http.csrf().disable().authorizeRequests().antMatchers("/**/authenticate","/swagger-ui.html", "/swagger-ui/**", "/v2/api-docs/**", "/swagger-resources/**").permitAll()
               .anyRequest().authenticated().and().sessionManagement()
               .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

       http.addFilterBefore(jwtFilterRequest, UsernamePasswordAuthenticationFilter.class);
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
