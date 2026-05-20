package com.application.authentication.utils;

import com.application.authentication.model.Users;
import com.application.authentication.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class AuthUtils {

    @Autowired
    private UserRepository userRepository;

    // Get logged-in username
    public String loggedInUsername(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(authentication == null || !authentication.isAuthenticated()){
            return null;
        }
        return authentication.getName();
    }

    // Get logged-in full user object
    public Users loggedInUser(){
        String username = loggedInUsername();
        if(username == null){
            return null;
        }
        return userRepository.findByUsername(username).orElse(null);
    }

    // Get logged-in userId
    public String loggedInUserId() {
        Users user = loggedInUser();
        return user != null ? user.getUserId() : null;
    }

}
