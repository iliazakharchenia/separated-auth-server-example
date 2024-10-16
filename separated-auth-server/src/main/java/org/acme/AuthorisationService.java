package org.acme;

import jakarta.inject.Singleton;

import java.util.concurrent.ConcurrentHashMap;

@Singleton
public class AuthorisationService {
    private final ConcurrentHashMap<String, String> mockedUsersData;

    public AuthorisationService() {
        this.mockedUsersData = new ConcurrentHashMap<>();

        // data mocking
        this.mockedUsersData.put("username", "password");
    }

    public boolean login(String username, String password) {
        // mocked login functionality
        if (mockedUsersData.containsKey(username))
            return mockedUsersData.get(username).equals(password);

        return false;
    }
}
