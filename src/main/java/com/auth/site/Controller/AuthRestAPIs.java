package com.auth.site.Controller;

import com.auth.site.Message.Request.LoginForm;
import com.auth.site.Message.Request.SignUpForm;
import com.auth.site.Message.Response.JwtResponse;
import com.auth.site.Model.Role;
import com.auth.site.Model.RoleName;
import com.auth.site.Model.User;
import com.auth.site.Repository.RoleRepository;
import com.auth.site.Repository.UserRepository;
import com.auth.site.Security.jwt.JwtProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.Set;

@CrossOrigin(origins="*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthRestAPIs {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtProvider jwtProvider;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginForm loginRequest){
        Authentication authentication = authenticationManager.authenticate( new UsernamePasswordAuthenticationToken(
                loginRequest.getUsername(),
                loginRequest.getPassword()
        ));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtProvider.generateJwtToken(authentication);
        return ResponseEntity.ok(new JwtResponse(jwt));
    }

    @PostMapping("/signup")
    public  ResponseEntity<String>registerUser(@Valid @RequestBody SignUpForm signUpRequest){
        if (userRepository.existsByUsername(signUpRequest.getUsername())){
            return new ResponseEntity<String>("Fail -> Username is already taken", HttpStatus.BAD_REQUEST);
        }

        if(userRepository.existsByEmail(signUpRequest.getEmail())) {
            return new ResponseEntity<String>("Fail -> Email is already in use!",
                    HttpStatus.BAD_REQUEST);
        }

        //Creating user's account
        User user = new User(signUpRequest.getName(), signUpRequest.getUsername(), signUpRequest.getEmail(), encoder.encode(signUpRequest.getPassword()));
        Set<String> strRoles = signUpRequest.getRole();
        Set<Role>roles = new HashSet<>();
        strRoles.forEach(role -> {
            switch (role){
                case  "admin":
                    Role adminRole = roleRepository.findByName(RoleName.ROLE_ADMIN)
                            .orElseThrow(() ->new  RuntimeException("Fail! -> Cause: User Role not found"));
                    roles.add(adminRole);

                    break;

                case  "pm":
                    Role pmRole = roleRepository.findByName(RoleName.ROLE_PM)
                            .orElseThrow(() ->new  RuntimeException("Fail! -> Cause: User Role not found"));
                    roles.add(pmRole);
                    break;

                 default:
                     Role userRole = roleRepository.findByName(RoleName.ROLE_USER)
                             .orElseThrow(() ->new  RuntimeException("Fail! -> Cause: User Role not found"));
                     roles.add(userRole);
            }
        });

        user.setRoles(roles);
        userRepository.save(user);

        return  ResponseEntity.ok().body("User Registred successfully");
    }
}
