package com.gtel.srpingtutorial.service;

import com.gtel.srpingtutorial.entity.AirportEntity;
import com.gtel.srpingtutorial.entity.LocationEntity;
import com.gtel.srpingtutorial.exception.ApplicationException;
import com.gtel.srpingtutorial.model.request.AirportRequest;
import com.gtel.srpingtutorial.model.request.LocationRequest;
import com.gtel.srpingtutorial.model.response.AirportResponse;
import com.gtel.srpingtutorial.redis.entities.AirportRedisEntity;
import com.gtel.srpingtutorial.redis.repository.AirportRedisRepository;
import com.gtel.srpingtutorial.repository.AirportRepository;
import com.gtel.srpingtutorial.repository.CustomAirportRepository;
import com.gtel.srpingtutorial.repository.LocationRepository;
import com.gtel.srpingtutorial.repository.secification.AirPortSpecification;
import com.gtel.srpingtutorial.utils.ERROR_CODE;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.*;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
@Log4j2
public class AirportService extends BaseService {


    private final AirportRepository airportRepository;

    private final CustomAirportRepository customAirportRepository;

    private final AirportRedisRepository airportRedisRepository;

    private final LocationRepository locationRepository;
    public AirportService(AirportRepository airportRepository, CustomAirportRepository customAirportRepository, AirportRedisRepository airportRedisRepository, LocationRepository locationRepository){
        this.airportRepository = airportRepository;
        this.customAirportRepository = customAirportRepository;
        this.airportRedisRepository = airportRedisRepository;
        this.locationRepository = locationRepository;
    }

    public List<AirportResponse> getAirportsNo4(Map<String, String> params) {


        List<AirportEntity> entities = customAirportRepository.getCustomSearch(params);
        List<AirportResponse> responses = new LinkedList<>();
        if (!CollectionUtils.isEmpty(entities)){
            responses.addAll(entities.stream().map(AirportResponse::new).toList());
        }

        return responses;
    }


//    public List<AirportResponse> getAirportsNo3(Map<String, String> params) {
//
//        int page = validatePage(getParam(params , "page" , 1)) - 1;
//
//        int pageSize = validatePageSize(getParam(params , "pageSize" , 10));
//
//        Specification<AirportEntity> specification = AirPortSpecification.getSpec(params);
//        Pageable pageable = PageRequest.of(page, pageSize);
//        Page<AirportEntity> entities = airportRepository.findAll(specification , pageable);
//        List<AirportResponse> responses = new LinkedList<>();
//        if (entities.hasContent()){
//            responses.addAll(entities.stream().map(AirportResponse::new).toList());
//        }
//
//
//        return responses;
//    }
    public List<AirportResponse> getAirportsNo2(Map<String, String> params) {

        int page = validatePage(getParam(params , "page" , 1)) - 1;

        int pageSize = validatePageSize(getParam(params , "pageSize" , 10));

        String name  = params.get("name");

        String airportgroupcode  = params.get("airportgroupcode");

        String language  = params.get("language");

        Integer priority = getParam(params , "priority");

        AirportEntity filter = new AirportEntity();
        if (StringUtils.isNotBlank(name)){
            filter.setName(name);
        }
        if (StringUtils.isNotBlank(airportgroupcode)){
            filter.setAirportgroupcode(airportgroupcode);
        }

        if (StringUtils.isNotBlank(language)){
            filter.setLanguage(language);
        }

        if (priority != null){
            filter.setPriority(priority);
        }

       List<AirportEntity> pageEntity = this.searchAirport(filter);

        List<AirportResponse> responses = new LinkedList<>();

        if (!CollectionUtils.isEmpty(pageEntity))
            responses.addAll(pageEntity.stream().map(AirportResponse::new).toList());

        return responses;
    }




    private List<AirportEntity> searchAirport(AirportEntity entity){

        ExampleMatcher matcher = ExampleMatcher.matching()
                .withIgnoreNullValues()
                .withIgnoreCase()
                .withStringMatcher(ExampleMatcher.StringMatcher.CONTAINING);
        Example<AirportEntity> example = Example.of(entity, matcher);

        return airportRepository.findAll(example);

    }
    public int countAirports() {
        return 0;
    }

    public AirportResponse getAirport(String iata) {

        Optional<AirportRedisEntity> cacheOpt = airportRedisRepository.findById(iata);

        if (cacheOpt.isPresent()){
            return cacheOpt.get().getData();
        }

        Optional<AirportEntity> optional = airportRepository.findById(iata);

        if (optional.isEmpty()){
            throw new ApplicationException(ERROR_CODE.INVALID_REQUEST , "Airport not found");
        }

        AirportEntity entity = optional.get();


        AirportRedisEntity newRedisEntity = new AirportRedisEntity();
        newRedisEntity.setCode(iata);
        AirportResponse response = new AirportResponse(entity);
        newRedisEntity.setData(response);
        newRedisEntity.setTimeToLive(1000);

        airportRedisRepository.save(newRedisEntity);
        return response;
    }

    @Cacheable(value = "airport", key = "#iata")
    public AirportResponse getAirport2(String iata) {

        Optional<AirportEntity> optional = airportRepository.findById(iata);

        if (optional.isEmpty()){
            throw new ApplicationException(ERROR_CODE.INVALID_REQUEST , "Airport not found");
        }
        AirportEntity entity = optional.get();
        return new AirportResponse(entity);
    }


    @Transactional(noRollbackForClassName = {"App"})
    public void createAirport(AirportRequest airportRequest) throws ApplicationException {
        log.info("createAirport with id  {} - name {} " , airportRequest.getIata() , airportRequest.getName());

        // 1. validate request
        this.validateCreateAirPort(airportRequest);

        // 2. check with ista


        this.createAirportFunction(airportRequest);
        try {
            this.createLocation(airportRequest.getLocation());
        }catch (Exception e){
            e.getMessage();
        }

        log.info("createAirport with id  {} SUCCESS " , airportRequest.getIata());
    }

    protected void createLocation(LocationRequest request){

        if (StringUtils.isBlank(request.getName()))
            throw new ApplicationException(ERROR_CODE.INVALID_PARAMETER , "location name is not empty");
        LocationEntity locationEntity = new LocationEntity();
//        locationEntity.setName(request.getName());
        locationEntity.setCode(request.getCode());
        locationEntity.setDescription(request.getDescription());

        locationRepository.save(locationEntity);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    protected void createAirportFunction(AirportRequest airportRequest){
        Optional<AirportEntity> airportOpt = airportRepository.findById(airportRequest.getIata());

        if (airportOpt.isPresent()){
            log.info("createAirport with id  {} FAIL, iata is existed on db " , airportRequest.getIata());

            throw new ApplicationException(ERROR_CODE.INVALID_REQUEST , "The iata is existed on system");
        }

        AirportEntity entity = new AirportEntity(airportRequest);

        airportRepository.save(entity);

    }



    public void deleteAirport(String iata) {
    }

    public void updateAirports(String iata, AirportRequest airportRequest) {
    }

    public void updatePathAirports(String iata, AirportRequest airportRequest) {
    }


    public void validateCreateAirPort(AirportRequest airportRequest) throws ApplicationException{

        if (StringUtils.isBlank(airportRequest.getIata())){
            throw new ApplicationException(ERROR_CODE.INVALID_PARAMETER , "iata code is not empty");
        }

        if (StringUtils.isBlank(airportRequest.getName())){
            throw new ApplicationException(ERROR_CODE.INVALID_PARAMETER , "name is not empty");
        }
    }
}
