package com.scrt.identity.repository;

import com.scrt.identity.domain.Application;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface ApplicationRepository extends JpaRepository<Application, UUID> {

    Optional<Application> findByClientId(String clientId);
}