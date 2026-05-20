package com.application.authentication.feignService;

import com.application.authentication.dtos.RoleRespDto;
import com.application.authentication.dtos.TokenIntrospectionResponse;
import com.application.authentication.model.Roles;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

@FeignClient(name = "roles", url = "${digital.app.roles}")
public interface RolesClient {

    @GetMapping("/api/role/rolesByUserId")
    List<RoleRespDto> getRolesByUserId(@RequestParam String userId);

    @GetMapping("/findByRoleType")
    Roles getRoleByRoleType(@RequestParam String roleType);

    @PostMapping("/api/role-mapping/assign")
    void createUserRoleMapping(@RequestHeader("X-INTERNAL-KEY") String internalKey,
                               @RequestParam("roleType") String roleType,
                               @RequestParam("userId") String userId);

    @GetMapping("/api/auth/introspect")
    TokenIntrospectionResponse introspect(@RequestHeader("Authorization") String authorization);

    // ✅ new PUBLIC endpoint (no auth required)
    @PostMapping("/api/user/public/userRoleMappings/default")
    void assignDefaultRole(@RequestParam("userId") String userId);

    @GetMapping("/api/internal/roles/delegates/count")
    Long countDelegates(@RequestHeader("X-INTERNAL-KEY") String internalKey);
}
