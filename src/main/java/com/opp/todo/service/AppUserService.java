package com.opp.todo.service;

import com.opp.todo.model.AppUser;
import com.opp.todo.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class AppUserService implements UserDetailsService {

    private UserRepository userRepository;



    public AppUserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
                .orElseThrow(()->new UsernameNotFoundException("Could not find user"));
    }

    public AppUser getUser(Long id){
        return userRepository.findById(id)
                .orElseThrow(()->new UsernameNotFoundException("User does not exist"));
    }
    public AppUser getUser(String username){
        return userRepository.findByUsername(username)
                .orElseThrow(()->new UsernameNotFoundException("User does not exist"));
    }

    public AppUser addUser(AppUser appUser){
        return userRepository.save(appUser);
    }

}
