package eu.sixtobuide.spring.boot.rest.api.secure.security;

import eu.sixtobuide.spring.boot.rest.api.secure.entity.User;
import eu.sixtobuide.spring.boot.rest.api.secure.repo.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class SecurityUtils {

    private UserRepository userRepository;

    @Autowired
    public SecurityUtils(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public User getLoginUser()
    {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(authentication != null)
        {
            User user = (User) authentication.getPrincipal();
            return userRepository.findByUsername(user.getUsername());
        }
        return null;
    }
}
