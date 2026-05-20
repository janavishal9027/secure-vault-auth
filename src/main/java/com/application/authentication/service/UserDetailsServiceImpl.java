package com.application.authentication.service;

import com.application.authentication.dtos.RoleRespDto;
import com.application.authentication.feignService.RolesClient;
import com.application.authentication.model.Roles;
import com.application.authentication.model.Users;
import com.application.authentication.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;
    private final RolesClient rolesClient;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Users users = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

        List<RoleRespDto> roles = rolesClient.getRolesByUserId(users.getUserId());
        if (roles == null || roles.isEmpty()) {
            roles = List.of(RoleRespDto
                    .builder()
                    .roleType("ROLE_CUSTOMER")
                    .build());
        }
        users.setRoles(roles);

        return UserDetailImpl.build(users);
    }
}
