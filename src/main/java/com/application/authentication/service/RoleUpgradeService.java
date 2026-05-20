package com.application.authentication.service;


import com.application.authentication.dtos.RoleUpgradeCreateRequest;
import com.application.authentication.dtos.RoleUpgradeResponse;

import java.util.List;

public interface RoleUpgradeService {

    RoleUpgradeResponse requestAdmin(RoleUpgradeCreateRequest roleUpgradeCreateRequest);

    List<RoleUpgradeResponse> pendingRequests();

    List<RoleUpgradeResponse> myRequests();

    RoleUpgradeResponse approve(String requestId);

    RoleUpgradeResponse reject(String requestId);

}
