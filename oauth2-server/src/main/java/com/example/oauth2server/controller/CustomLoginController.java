package com.example.oauth2server.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class CustomLoginController {

    @GetMapping("/login")
    public String login(@RequestParam(value = "error", required = false) String error,
                       @RequestParam(value = "logout", required = false) String logout,
                       @RequestParam(value = "client_id", required = false) String clientId,
                       @RequestParam(value = "scope", required = false) String scope,
                       @RequestParam(value = "state", required = false) String state,
                       @RequestParam(value = "redirect_uri", required = false) String redirectUri,
                       Model model) {
        
        if (error != null) {
            model.addAttribute("error", "Invalid username or password.");
        }
        
        if (logout != null) {
            model.addAttribute("message", "You have been logged out successfully.");
        }
        
        // Add OAuth2 parameters to the model for the form
        model.addAttribute("clientId", clientId);
        model.addAttribute("scope", scope);
        model.addAttribute("state", state);
        model.addAttribute("redirectUri", redirectUri);
        
        return "login";
    }
}
