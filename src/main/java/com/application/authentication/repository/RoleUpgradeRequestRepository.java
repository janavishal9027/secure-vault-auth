package com.application.authentication.repository;

import com.application.authentication.model.RoleUpgradeRequest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RoleUpgradeRequestRepository extends JpaRepository<RoleUpgradeRequest, String> {

    boolean existsByUserIdAndToRoleAndStatus(String userId, String toRole, String status);

    List<RoleUpgradeRequest> findByStatusOrderByCreatedAtDesc(String status);

    List<RoleUpgradeRequest> findByUserIdOrderByCreatedAtDesc(String userId);

}
