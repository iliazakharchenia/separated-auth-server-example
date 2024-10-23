package org.acme;

import io.quarkus.runtime.Startup;
import jakarta.inject.Singleton;
import jakarta.ws.rs.NotFoundException;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Singleton
@Startup
public class AuthorisationService {
    private final Map<String, String> mockedUsersData;
    private final Map<String, Set<String>> mockedUsersRoles;

    public AuthorisationService() {
        this.mockedUsersData = new ConcurrentHashMap<>();
        this.mockedUsersRoles = new ConcurrentHashMap<>();

        // data mocking
        this.mockedUsersData.put("username", "password");
        this.mockedUsersRoles.put("username", Set.of("USER", "READ"));
    }

    public UserData login(String username, String password) {
        // mocked login functionality
        if (mockedUsersData.containsKey(username))
            if (mockedUsersData.get(username).equals(password))
                return new UserData(username, mockedUsersRoles.get(username));

        throw new NotFoundException("User with such username and password is not exists!");
    }

    record UserData(String name, Set<String> roles) {}
}
