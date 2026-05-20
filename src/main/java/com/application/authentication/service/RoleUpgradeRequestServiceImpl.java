package com.application.authentication.service;



import com.application.authentication.dtos.RoleUpgradeCreateRequest;
import com.application.authentication.dtos.RoleUpgradeResponse;
import com.application.authentication.feignService.RolesClient;
import com.application.authentication.model.RoleUpgradeRequest;
import com.application.authentication.model.Users;
import com.application.authentication.repository.RoleUpgradeRequestRepository;
import com.application.authentication.utils.AuthUtils;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@Slf4j
public class RoleUpgradeRequestServiceImpl implements RoleUpgradeService{

    @Autowired
    private RoleUpgradeRequestRepository roleUpgradeRequestRepository;

    @Autowired
    private AuthUtils authUtils;

    @Autowired
    private RolesClient rolesClient;

    @Autowired
    private ModelMapper modelMapper;

    // CUSTOMER raises request ---------> To upgrade the role to ADMIN
    @Override
    public RoleUpgradeResponse requestAdmin(RoleUpgradeCreateRequest roleUpgradeCreateRequest) {
        Users users = authUtils.loggedInUser();
        if (users == null) throw new RuntimeException("Unauthorized");
        boolean exists = roleUpgradeRequestRepository.existsByUserIdAndToRoleAndStatus(users.getUserId(), "ADMIN", "PENDING");
        if (exists) throw new RuntimeException("You already have a pending request for admin role");
        RoleUpgradeRequest roleUpgradeRequest = RoleUpgradeRequest.builder()
                .requestId("REQ" + LocalDateTime.now().getYear() + LocalDateTime.now().getDayOfYear() + LocalDateTime.now().getSecond() + LocalDateTime.now().getNano())
                .userId(users.getUserId())
                .username(users.getUsername())
                .fromRole("CUSTOMER")
                .toRole("ADMIN")
                .status("PENDING")
                .reason(roleUpgradeCreateRequest != null ? roleUpgradeCreateRequest.getReason() : null)
                .createdAt(LocalDateTime.now())
                .build();

        return modelMapper.map(roleUpgradeRequestRepository.save(roleUpgradeRequest), RoleUpgradeResponse.class);

    }

    // DELEGATE views pending
    @Override
    public List<RoleUpgradeResponse> pendingRequests() {
        return roleUpgradeRequestRepository.findByStatusOrderByCreatedAtDesc("PENDING")
                .stream()
                .map(request -> modelMapper.map(request, RoleUpgradeResponse.class))
                .collect(Collectors.toList());
    }

    // CUSTOMER can view own requests
    @Override
    public List<RoleUpgradeResponse> myRequests() {
        Users users = authUtils.loggedInUser();
        if(users == null) throw new RuntimeException("Unauthorized");
        return roleUpgradeRequestRepository.findByUserIdOrderByCreatedAtDesc(users.getUserId())
                .stream()
                .map(request -> modelMapper.map(request, RoleUpgradeResponse.class))
                .collect(Collectors.toList());
    }

    // DELEGATE approves: assigns ROLE_ADMIN in Roles service
    @Override
    public RoleUpgradeResponse approve(String requestId) {
        Users reviewer = authUtils.loggedInUser();
        if(reviewer == null) throw new RuntimeException("Unauthorized");

        RoleUpgradeRequest roleUpgradeRequest = roleUpgradeRequestRepository.findById(requestId).orElseThrow(() -> new RuntimeException("Request not found"));

        if(!"PENDING".equals(roleUpgradeRequest.getStatus())) throw new RuntimeException("Already processed");

        rolesClient.createUserRoleMapping("MY_SUPER_SECRET_KEY","ADMIN", roleUpgradeRequest.getUserId());

        roleUpgradeRequest.setStatus("APPROVED");
        roleUpgradeRequest.setReviewedBy(reviewer.getUsername());
        roleUpgradeRequest.setReviewedAt(LocalDateTime.now());

        return modelMapper.map(roleUpgradeRequestRepository.save(roleUpgradeRequest), RoleUpgradeResponse.class);
    }

    // DELEGATE rejects
    @Override
    public RoleUpgradeResponse reject(String requestId) {
        Users reviewer = authUtils.loggedInUser();
        if(reviewer == null) throw new RuntimeException("Unauthorized");

        RoleUpgradeRequest roleUpgradeRequest = roleUpgradeRequestRepository.findById(requestId).orElseThrow(() -> new RuntimeException("Request not found"));

        if(!"PENDING".equals(roleUpgradeRequest.getStatus())) throw new RuntimeException("Already processed");

        roleUpgradeRequest.setStatus("REJECTED");
        roleUpgradeRequest.setReviewedBy(reviewer.getUsername());
        roleUpgradeRequest.setReviewedAt(LocalDateTime.now());
        return modelMapper.map(roleUpgradeRequestRepository.save(roleUpgradeRequest), RoleUpgradeResponse.class);
    }
}
