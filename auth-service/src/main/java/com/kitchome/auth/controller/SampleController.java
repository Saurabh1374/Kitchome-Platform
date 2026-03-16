package com.kitchome.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class SampleController {
	
	@GetMapping("/public")
	public ResponseEntity<String> hello(){
		return ResponseEntity.ok("hello world");
	}
	@GetMapping("/private")
	public ResponseEntity<?> privatehello(){
		return ResponseEntity.ok("Hello Sir, How may i help you");
	}

}
