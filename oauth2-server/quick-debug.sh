# Quick Debug Commands

# 1. Kill any processes using ports 8080 or 5389
lsof -ti :8080 | xargs kill -9 2>/dev/null || echo 'No process on 8080'
lsof -ti :5389 | xargs kill -9 2>/dev/null || echo 'No process on 5389'

# 2. Run with enhanced logging
mvn spring-boot:run -Dspring-boot.run.arguments="--logging.level.org.springframework=DEBUG,--logging.level.com.example=DEBUG"

# 3. Test OAuth2 flow
curl -c cookies.txt -s 'http://localhost:8080/oauth2/authorize?response_type=code&client_id=client1&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=read+write&state=test123' > /dev/null && curl -b cookies.txt -s 'http://localhost:8080/login' | grep -E '(client_id|scope|state|redirect_uri)' | head -5

# 4. View logs in real-time
tail -f logs/oauth2-server.log
