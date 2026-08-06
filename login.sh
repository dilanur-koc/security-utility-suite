#!/bin/bash
curl -s -c ~/IdeaProjects/security-utility-suite/cookies.txt \
  -X POST http://localhost:8080/perform-login \
  -d "username=test&password=Test1234!" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -o /dev/null -w "Login status: %{http_code}\n"
