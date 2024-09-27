package com.example.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.example.demo.loginform.LoginForm;

@Controller
@RequestMapping
public class LoginController {
	 
	
	  // 定義GET請求的路徑 /lswebsite/login
	@GetMapping("/admin/manage-users/login")
	public String login(Model model) {
		LoginForm loginForm = new LoginForm();
		System.out.println("loginFrom :"+ loginForm);
		model.addAttribute("LoginForm",loginForm); //Add form-backing object
		System.out.println("Loginform added to model: " + loginForm);
		
//		return "../templates/admin/login";
		return "admin/login";
		// 返回 login.html 模板頁面
	}
	

}
