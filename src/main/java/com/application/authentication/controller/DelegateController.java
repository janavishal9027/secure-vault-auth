package com.application.authentication.controller;

import com.application.authentication.dtos.UserAuthDto;
import com.application.authentication.request.DelegateSignUpRequest;
import com.application.authentication.service.UserAuthentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/delegate")
public class DelegateController {

    @Autowired
    private UserAuthentication userAuthentication;

    @PostMapping("/signup-delegate")
    public ResponseEntity<UserAuthDto> signUpDelegate(
            @RequestBody DelegateSignUpRequest request,
            @RequestHeader("X-Delegate-Bootstrap-Key") String bootstrapKey
    ) {
        System.out.println("DelegateController hit");
        UserAuthDto response = userAuthentication.signUpDelegate(request, bootstrapKey);
        System.out.println("Response from service = " + response);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

}
