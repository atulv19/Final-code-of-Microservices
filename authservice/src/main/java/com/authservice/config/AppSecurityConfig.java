package com.authservice.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.authservice.service.CustomerUserDetailsService;

@Configuration
@EnableWebSecurity
public class AppSecurityConfig {
	
	@Autowired
	private CustomerUserDetailsService customerUserDetailsService;
	
	@Autowired
	private JwtFilter filter;

    private String[] OpenUrl = {
            "/api/v1/auth/register",
            "/api/v1/auth/login",// ✅ fixed here
            "/v3/api-docs/**",
            "/swagger-ui/**",
            "/swagger-ui.html",
            "/swagger-resources/**",
            "/webjars/**"
    };
    
    
    @Bean
   	public AuthenticationManager authManager(AuthenticationConfiguration config) throws Exception {
   		return config.getAuthenticationManager();
   	}
    
    @Bean
   	public AuthenticationProvider authProvider() {

   		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
   		authProvider.setUserDetailsService(customerUserDetailsService);
   		authProvider.setPasswordEncoder(getEncodedPassword());
   		return authProvider;
   	}


    @Bean
    public PasswordEncoder getEncodedPassword() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityConfig(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(req -> req
                .requestMatchers(OpenUrl).permitAll()
                .requestMatchers("api/v1/welcome").hasAnyRole("USER")
                .anyRequest().authenticated()
            ) .authenticationProvider(authProvider())
            .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
        
        return http.csrf().disable().build();
    }
}
