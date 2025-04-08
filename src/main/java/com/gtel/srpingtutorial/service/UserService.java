package com.gtel.srpingtutorial.service;

import com.gtel.srpingtutorial.domains.OtpDomain;
import com.gtel.srpingtutorial.entity.UserEntity;
import com.gtel.srpingtutorial.exception.ApplicationException;
import com.gtel.srpingtutorial.model.request.ConfirmOtpRegisterRequest;
import com.gtel.srpingtutorial.model.request.RegisterRequest;
import com.gtel.srpingtutorial.model.response.RegisterResponse;
import com.gtel.srpingtutorial.redis.entities.RegisterUserEntity;
import com.gtel.srpingtutorial.redis.repository.RegisterUserRedisRepository;
import com.gtel.srpingtutorial.repository.UserRepository;
import com.gtel.srpingtutorial.utils.ERROR_CODE;
import com.gtel.srpingtutorial.utils.PhoneNumberUtils;
import com.gtel.srpingtutorial.utils.USER_STATUS;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class UserService  extends BaseService{

    private final OtpDomain otpDomain;

    private final UserRepository userRepository;

    private final RegisterUserRedisRepository registerUserRedisRepository;

    public UserService(OtpDomain otpDomain, UserRepository userRepository, RegisterUserRedisRepository registerUserRedisRepository) {
        this.otpDomain = otpDomain;
        this.userRepository = userRepository;
        this.registerUserRedisRepository = registerUserRedisRepository;
    }

    public RegisterResponse registerUser(RegisterRequest request) throws ApplicationException {

        //validate request
        this.validateUserRegisterRequest(request);

        // check user exist on db
        String phoneNumber = PhoneNumberUtils.validatePhoneNumber(request.getPhoneNumber());
        log.info("[registerUser] - user register with phone {} START", phoneNumber);

        UserEntity userEntity = userRepository.findByPhoneNumber(phoneNumber);

        if (userEntity != null){
            log.info("[registerUser] request fail : user already exists with phone {}", phoneNumber);
            throw new ApplicationException(ERROR_CODE.INVALID_REQUEST, "PhoneNumber is already exists");
        }
        // otp gen
        RegisterUserEntity otpEntity = otpDomain.genOtpWhenUserRegister(phoneNumber, request.getPassword());
        //log.debug("[registerUser] - user register with phone entity {} ", otpEntity);
        log.info("[registerUser] - user register with phone {} DONE", request.getPhoneNumber());
        return new RegisterResponse(otpEntity);
    }

    protected void validateUserRegisterRequest(RegisterRequest request) throws ApplicationException {
        if (StringUtils.isBlank(request.getPhoneNumber())) {
            throw new ApplicationException(ERROR_CODE.INVALID_PARAMETER , "phoneNumber is invalid");
        }


        if (StringUtils.isBlank(request.getPassword())) {
            throw new ApplicationException(ERROR_CODE.INVALID_PARAMETER , "password is invalid");
        }

        com.gtel.srpingtutorial.utils.StringUtils.validatePassword(request.getPassword());
    }


    public RegisterResponse resendOtp(String transactionId) throws ApplicationException {
        log.info("[resendOtp] - resend with transactionId {}", transactionId);

        RegisterUserEntity entity = registerUserRedisRepository.findById(transactionId)
                .orElseThrow(() -> new ApplicationException(ERROR_CODE.INVALID_REQUEST, "Transaction ID not found"));

        long now = System.currentTimeMillis() / 1000;

        if (now < entity.getOtpResendTime()) {
            throw new ApplicationException(ERROR_CODE.INVALID_REQUEST, "Please wait 120s");
        }

        if (entity.getOtpResendCount() >= 5) {
            throw new ApplicationException(ERROR_CODE.INVALID_REQUEST, "OTP is only sent 5 times a day");
        }

        entity.setOtp(otpDomain.genOtp());
        entity.setOtpResendTime(now + 60);
        entity.setOtpResendCount(entity.getOtpResendCount() + 1);

        registerUserRedisRepository.save(entity);

        log.info("[resendOtp] - OTP resent successfully for transactionId {}", transactionId);
        log.info("[otp new] - OTP resent {}", entity.getOtp());

        return new RegisterResponse(entity);
    }

    public void confirmRegisterOtp(ConfirmOtpRegisterRequest request) throws ApplicationException {
        log.info("[confirmRegisterOtp] - Start with transactionId {}", request.getTransactionId());

        RegisterUserEntity entity = registerUserRedisRepository.findById(request.getTransactionId())
                .orElseThrow(() -> new ApplicationException(ERROR_CODE.INVALID_REQUEST, "Transaction ID not found"));

        long now = System.currentTimeMillis() / 1000;

        if (now > entity.getOtpExpiredTime()) {
            throw new ApplicationException(ERROR_CODE.INVALID_REQUEST, "OTP expired");
        }

        if (!entity.getOtp().equals(request.getOtp())) {
            entity.setOtpFail(entity.getOtpFail() + 1);
            registerUserRedisRepository.save(entity);

            if (entity.getOtpFail() >= 5) {
                throw new ApplicationException(ERROR_CODE.INVALID_REQUEST, "OTP failed 5 times. Please try again later.");
            }

            throw new ApplicationException(ERROR_CODE.INVALID_REQUEST, "Invalid OTP");
        }

        UserEntity user = new UserEntity();
        user.setPhoneNumber(entity.getPhoneNumber());
        user.setPassword(entity.getPassword());
        user.setStatus(USER_STATUS.ACTIVE);

        userRepository.save(user);
        registerUserRedisRepository.delete(entity);

        log.info("[confirmRegisterOtp] - OTP confirmed successfully for transactionId {}", request.getTransactionId());
    }

}
