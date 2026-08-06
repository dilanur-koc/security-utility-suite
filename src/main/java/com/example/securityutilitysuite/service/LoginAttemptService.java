package com.example.securityutilitysuite.service;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class LoginAttemptService {

    private static final int MAX_ATTEMPTS = 5;
    private static final long LOCK_TIME_DURATION_MILLIS = 15 * 60 * 1000;

    private final Map<String, Integer> attemptsCache = new ConcurrentHashMap<>();
    private final Map<String, Long> lockTimeCache = new ConcurrentHashMap<>();

    public void loginSucceeded(String key) {
        attemptsCache.remove(key);
        lockTimeCache.remove(key);
    }

    public void loginFailed(String key) {
        int attempts = attemptsCache.getOrDefault(key, 0) + 1;
        attemptsCache.put(key, attempts);

        if (attempts >= MAX_ATTEMPTS) {
            lockTimeCache.put(key, Instant.now().toEpochMilli() + LOCK_TIME_DURATION_MILLIS);
        }
    }

    public boolean isBlocked(String key) {
        if (!lockTimeCache.containsKey(key)) {
            return false;
        }

        long lockTime = lockTimeCache.get(key);
        if (Instant.now().toEpochMilli() > lockTime) {
            lockTimeCache.remove(key);
            attemptsCache.remove(key);
            return false;
        }

        return true;
    }

    public int getRemainingAttempts(String key) {
        int attempts = attemptsCache.getOrDefault(key, 0);
        return Math.max(0, MAX_ATTEMPTS - attempts);
    }
}
