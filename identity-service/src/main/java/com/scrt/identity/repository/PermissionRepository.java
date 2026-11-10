package com.scrt.identity.repository;

import com.scrt.identity.domain.Permission;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface PermissionRepository extends JpaRepository<Permission, UUID> {

    Optional<Permission> findByApplicationIdAndCode(UUID applicationId, String code);
}