package com.gtel.srpingtutorial.api;

import com.gtel.srpingtutorial.exception.ApplicationException;
import com.gtel.srpingtutorial.model.request.ConfirmOtpRegisterRequest;
import com.gtel.srpingtutorial.model.request.RegisterRequest;
import com.gtel.srpingtutorial.model.response.RegisterResponse;
import com.gtel.srpingtutorial.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1/user")
public class UserController {

    @Autowired
    UserService userService;
    // 1. register
    @PostMapping("/register")
    public RegisterResponse register(@RequestBody RegisterRequest registerRequest) throws ApplicationException {
        return userService.registerUser(registerRequest);
    }

    @GetMapping("/resend-otp/{transactionId}")
    public RegisterResponse resendOtp(@PathVariable("transactionId") String transactionId) {
        return userService.resendOtp(transactionId);
    }

    //3. verify otp

    @PostMapping("/confirm-otp")
    public void confirmRegisterOtp(@RequestBody ConfirmOtpRegisterRequest request){
        userService.confirmRegisterOtp(request);
    }

}
