package com.example.demo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
//@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter  {
	
	@Override
	protected void configure(HttpSecurity http) throws Exception{
		// Submit form-data 
		http.formLogin()
			/*
			 * The '.loginProcessingUrl("/login")' method is used to specify the URL where the login form should be submitted. 
			 * It tells Spring Security where to send the POST request containing the user's credentials for authentication.
			 * 
			 * However, if you only specify '.loginPage("/loginpage")' without also configuring '.loginProcessingUrl("/login")', 
			 * Spring Security won't know where to process the login form submission.
			 * 
			 * When you configure .loginPage("/loginpage"), you're telling Spring Security that requests to '/loginpage' 
			 * should be treated as the login page for your application. 
			 * 
			 * This means that when a user attempts to access a secured resource without being authenticated, 
			 * Spring Security will redirect them to the '/loginpage' URL.
			 * 
			 * So, both .loginPage("/loginpage") and .loginProcessingUrl("/login") are necessary to properly configure Spring Security for form-based authentication. 
			 * 
			 * The former specifies the URL of the login page, and the latter specifies the URL where the login form should be submitted for processing.
			 */
		    .loginProcessingUrl("/login")
		    // Define a login-page in customization; otherwise, will redirect to the default login-page
		    .loginPage("/admin/manage-users/login") // .loginPage("/loginpage")
		    // login successfully then access a web-page
		    .successForwardUrl("/admin/manage-users/login") // e.g., '/homepage'		    
		    // login fail then access a web-page
		    .failureForwardUrl("/fail");

		// Authorization certificate
		/*
		 * This configuration is using authorizeRequests() method to define authorization rules. Here's what each line does:
		 * 
		 * .antMatchers("/loginpage").permitAll(): 
		 * 		
		 * 		This line specifies that requests to the "/loginpage" URL should be permitted for all users (permitAll()), meaning they can access this page without being authenticated.
		 * 
		 * .anyRequest().authenticated(): 
		 * 
		 * 		This line specifies that any request that doesn't match the previous rule (i.e., requests to URLs other than "/loginpage") must be authenticated. 
		 * 		In other words, any other request besides "/loginpage" requires the user to be authenticated.
		 */
		http.authorizeHttpRequests()
			// all visitors can access without authorization
			.antMatchers("/admin/manage-users/login").permitAll()
			// all visitors must be authenticated before access
			.anyRequest().authenticated();		
		
	}
	
	/*
	 * Notice here! This method 'getPasswordEncoder()' is indeed part of the regulation of Spring Security requiring an instance of a hashing algorithm for secure password handling.
	 * By defining a method like getPasswordEncoder() annotated with @Bean, you're instructing Spring to create and manage a PasswordEncoder bean. 
	 * In the provided code snippet, it's configured to return an instance of BCryptPasswordEncoder, which is a widely used and recommended hashing algorithm for password security.
	 * 
	 * For more detail of usage for 'BCryptPasswordEncoder()', please refer to SpringSecurityAuthenticationApplicationTests class.
	 */
	@Bean
	public PasswordEncoder getPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}	
    
}

