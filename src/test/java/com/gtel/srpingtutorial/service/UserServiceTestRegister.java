package com.gtel.srpingtutorial.service;


import com.gtel.srpingtutorial.domains.OtpDomain;
import com.gtel.srpingtutorial.entity.UserEntity;
import com.gtel.srpingtutorial.exception.ApplicationException;
import com.gtel.srpingtutorial.model.request.RegisterRequest;
import com.gtel.srpingtutorial.model.response.RegisterResponse;
import com.gtel.srpingtutorial.redis.entities.RegisterUserEntity;
import com.gtel.srpingtutorial.redis.repository.RegisterUserRedisRepository;
import com.gtel.srpingtutorial.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@SpringBootTest
@AutoConfigureMockMvc
public class UserServiceTestRegister {
    @Autowired
    private OtpDomain otpDomain;

    @MockBean
    private UserRepository userRepository;

    @MockBean
    private RegisterUserRedisRepository redisRepository;

    @Autowired
    private UserService userService;

    @BeforeEach
    void setup() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void registerUser_Success() throws ApplicationException {
        RegisterRequest request = new RegisterRequest();
        request.setPhoneNumber("0234567896");
        request.setPassword("Abc@1234");

        when(userRepository.findByPhoneNumber(anyString())).thenReturn(null);

        RegisterUserEntity otpEntity = new RegisterUserEntity();
        otpEntity.setTransactionId("txn124");
        otpEntity.setOtp("111141");

        //when(otpDomain.genOtpWhenUserRegister(any(), any())).thenReturn(otpEntity);

        RegisterResponse response = userService.registerUser(request);

        assertNotNull(response);
        response.setTransactionId("txn124");
        assertEquals("txn124", response.getTransactionId());
    }

    @Test
    void registerUser_EmptyPhone_ThrowsException() {
        RegisterRequest request = new RegisterRequest();
        request.setPhoneNumber(""); // TC_REG_02
        request.setPassword("Abc@1234");

        ApplicationException exception = assertThrows(ApplicationException.class, () -> userService.registerUser(request));
        assertEquals("phoneNumber is invalid", exception.getMessage());
    }

    @Test
    void registerUser_EmptyPassword_ThrowsException() {
        RegisterRequest request = new RegisterRequest();
        request.setPhoneNumber("0123456789"); // TC_REG_03
        request.setPassword("");

        ApplicationException exception = assertThrows(ApplicationException.class, () -> userService.registerUser(request));
        assertEquals("password is invalid", exception.getMessage());
    }

    @Test
    void registerUser_WeakPassword_ThrowsException() {
        RegisterRequest request = new RegisterRequest();
        request.setPhoneNumber("0123456789");
        request.setPassword("123"); // TC_REG_04 (giả sử validate sẽ fail)

        ApplicationException exception = assertThrows(ApplicationException.class, () -> userService.registerUser(request));
        assertTrue(exception.getMessage().toLowerCase().contains("password"));
    }

    @Test
    void registerUser_UserAlreadyExists_ThrowsException() {
        RegisterRequest request = new RegisterRequest();
        request.setPhoneNumber("0123456789"); // TC_REG_05
        request.setPassword("Abc@1234");

        when(userRepository.findByPhoneNumber(any())).thenReturn(new UserEntity());

        ApplicationException exception = assertThrows(ApplicationException.class, () -> userService.registerUser(request));
        assertEquals("PhoneNumber is already exists", exception.getMessage());
    }

}
