package com.gtel.srpingtutorial.service;


import com.gtel.srpingtutorial.exception.ApplicationException;
import com.gtel.srpingtutorial.model.request.ConfirmOtpRegisterRequest;
import com.gtel.srpingtutorial.redis.entities.RegisterUserEntity;
import com.gtel.srpingtutorial.redis.repository.RegisterUserRedisRepository;
import lombok.extern.slf4j.Slf4j;
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
public class UserServiceTestVerify {
    @MockBean
    private RegisterUserRedisRepository redisRepository;

    @Autowired
    private UserService userService;


    @Test
    void confirmOtp_TransactionNotFound_ThrowsException() {
        when(redisRepository.findById("txn123")).thenReturn(Optional.empty()); // TC_CONFIRM_05

        ConfirmOtpRegisterRequest request = new ConfirmOtpRegisterRequest();
        request.setTransactionId("txn123");
        request.setOtp("123");

        ApplicationException ex = assertThrows(ApplicationException.class, () -> userService.confirmRegisterOtp(request));
        assertEquals("Transaction ID not found", ex.getMessage());
    }

    @Test
    void confirmOtp_ExpiredOtp_ThrowsException() {
        RegisterUserEntity entity = new RegisterUserEntity();
        entity.setOtpExpiredTime(System.currentTimeMillis() / 1000 - 10); // expired
        entity.setOtp("123456");

        when(redisRepository.findById("txn123")).thenReturn(Optional.of(entity)); // TC_CONFIRM_04

        ConfirmOtpRegisterRequest request = new ConfirmOtpRegisterRequest();
        request.setTransactionId("txn123");
        request.setOtp("123456");

        ApplicationException ex = assertThrows(ApplicationException.class, () -> userService.confirmRegisterOtp(request));
        assertEquals("OTP expired", ex.getMessage());
    }

    @Test
    void confirmOtp_WrongOtp_Under5Tries_ThrowsException() {
        RegisterUserEntity entity = new RegisterUserEntity();
        entity.setOtpExpiredTime(System.currentTimeMillis() / 1000 + 60);
        entity.setOtp("999999");
        entity.setOtpFail(2); // < 5

        when(redisRepository.findById("txn123")).thenReturn(Optional.of(entity)); // TC_CONFIRM_02

        ConfirmOtpRegisterRequest request = new ConfirmOtpRegisterRequest();
        request.setTransactionId("txn123");
        request.setOtp("111111");

        ApplicationException ex = assertThrows(ApplicationException.class, () -> userService.confirmRegisterOtp(request));
        assertEquals("Invalid OTP", ex.getMessage());
    }

    @Test
    void confirmOtp_WrongOtp_Over5Tries_ThrowsException() {
        RegisterUserEntity entity = new RegisterUserEntity();
        entity.setOtpExpiredTime(System.currentTimeMillis() / 1000 + 60);
        entity.setOtp("123456");
        entity.setOtpFail(4); // 5th time sẽ throw khác
        when(redisRepository.findById("txn123")).thenReturn(Optional.of(entity));

        ConfirmOtpRegisterRequest request = new ConfirmOtpRegisterRequest();
        request.setTransactionId("txn123");
        request.setOtp("wrong");

        ApplicationException ex = assertThrows(ApplicationException.class, () -> userService.confirmRegisterOtp(request));
        assertEquals("OTP failed 5 times. Please try again later.", ex.getMessage());
    }

}
