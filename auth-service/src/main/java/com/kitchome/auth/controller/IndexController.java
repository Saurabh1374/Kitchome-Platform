package com.kitchome.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class IndexController {
	@GetMapping("/")
	public String index(Model model) {
		
		model.addAttribute("loginLink", "/login");
		model.addAttribute("registerLink", "/register");

		return "Index"; // Name of the Thymeleaf template (welcome.html)
	}
	@GetMapping("/invalidSession")
	public ResponseEntity invalidSession(){
        return ResponseEntity.ok("Under construction");
	}

}
