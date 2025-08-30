package com.example.oauth2server.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

@Controller
public class CustomLoginController {

    @GetMapping("/login")
    public String login(@RequestParam(value = "error", required = false) String error,
                       @RequestParam(value = "logout", required = false) String logout,
                       HttpServletRequest request,
                       Model model) {

        if (error != null) {
            model.addAttribute("error", "Invalid username or password.");
        }

        if (logout != null) {
            model.addAttribute("message", "You have been logged out successfully.");
        }

        // Extract OAuth2 parameters from saved request
        Map<String, String> oauth2Params = extractOAuth2Parameters(request);

        // Add OAuth2 parameters to the model for the form
        model.addAttribute("clientId", oauth2Params.get("client_id"));
        model.addAttribute("scope", oauth2Params.get("scope"));
        model.addAttribute("state", oauth2Params.get("state"));
        model.addAttribute("redirectUri", oauth2Params.get("redirect_uri"));

        return "login";
    }

    private Map<String, String> extractOAuth2Parameters(HttpServletRequest request) {
        Map<String, String> params = new HashMap<>();

        try {
            HttpSession session = request.getSession(false);
            if (session != null) {
                HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
                SavedRequest savedRequest = requestCache.getRequest(request, null);

                if (savedRequest instanceof DefaultSavedRequest) {
                    DefaultSavedRequest defaultSavedRequest = (DefaultSavedRequest) savedRequest;

                    // Extract parameters from the saved request URL
                    String requestUrl = defaultSavedRequest.getRequestURL();
                    String queryString = defaultSavedRequest.getQueryString();

                    if (queryString != null) {
                        // Parse query parameters
                        String[] pairs = queryString.split("&");
                        for (String pair : pairs) {
                            String[] keyValue = pair.split("=");
                            if (keyValue.length == 2) {
                                String key = URLDecoder.decode(keyValue[0], StandardCharsets.UTF_8);
                                String value = URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8);
                                params.put(key, value);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Log the exception if needed
            System.err.println("Error extracting OAuth2 parameters: " + e.getMessage());
        }

        return params;
    }
}
