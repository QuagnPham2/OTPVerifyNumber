package com.gtel.srpingtutorial.service;


import com.gtel.srpingtutorial.exception.ApplicationException;
import com.gtel.srpingtutorial.redis.entities.RegisterUserEntity;
import com.gtel.srpingtutorial.redis.repository.RegisterUserRedisRepository;
import lombok.extern.slf4j.Slf4j;
import org.checkerframework.checker.units.qual.A;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@Slf4j
@SpringBootTest
@AutoConfigureMockMvc
public class UserServiceTestResend {
    @MockBean
    private RegisterUserRedisRepository redisRepository;

    @Autowired
    private UserService userService;

    @Test
    void resendOtp_TransactionNotFound_ThrowsException() {
        when(redisRepository.findById("txn123")).thenReturn(Optional.empty()); // TC_RESEND_02

        ApplicationException ex = assertThrows(ApplicationException.class, () -> userService.resendOtp("txn123"));
        assertEquals("Transaction ID not found", ex.getMessage());
    }

    @Test
    void resendOtp_NotEnoughTimeToResend_ThrowsException() {
        RegisterUserEntity entity = new RegisterUserEntity();
        entity.setOtpResendTime(System.currentTimeMillis() / 1000 + 60); // not yet allowed

        when(redisRepository.findById("txn123")).thenReturn(Optional.of(entity)); // TC_RESEND_03

        ApplicationException ex = assertThrows(ApplicationException.class, () -> userService.resendOtp("txn123"));
        assertEquals("Please wait 120s", ex.getMessage());
    }

    @Test
    void resendOtp_ExceededMaxTimes_ThrowsException() {
        RegisterUserEntity entity = new RegisterUserEntity();
        entity.setOtpResendTime(System.currentTimeMillis() / 1000 - 60);
        entity.setOtpResendCount(5); // TC_RESEND_04

        when(redisRepository.findById("txn123")).thenReturn(Optional.of(entity));

        ApplicationException ex = assertThrows(ApplicationException.class, () -> userService.resendOtp("txn123"));
        assertEquals("OTP is only sent 5 times a day", ex.getMessage());
    }

}
