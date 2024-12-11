# Authentication service

## Environment variables
Variables are stored in [.env](.env) file.
+ ```DATABASE_URL``` - PostgresSQL database URL
+ ```SECRET_KEY``` - secret key for JWT token generation
+ ```SERVER_IP``` - server IP in ListenAndServe
+  ```SERVER_PORT``` server port in ListenAndServe
+  ```MAILTRAP_USERNAME``` - username from Mailtrap
+  ```MAILTRAP_PASSWORD``` - password from Mailtrap
+  ```FROM_EMAIL``` - the email we use to send emails in Mailtrap

## Deployment
[Dockerfile](Dockerfile) for server, server and database are deployed with [docker-compose.yml](docker-compose.yml).

## Module tests
Tests are in [database_test.go](internal/database/database_test.go), [services_test.go](internal/services/services_test.go) and [handlers_test.go](internal/transport/rest/handlers_test.go).

80%+ coverage.

![img.png](img.png)

## Documentation
Documentation is in [docs.go](docs/docs.go), [swagger.json](docs/swagger.json) and [swagger.yaml](docs/swagger.yaml).

## Routes
+ /create - the CreateTokens handler generates JWT access and refresh tokens using user's email and guid.
+ /refresh - the RefreshTokens handler refreshes access and refresh tokens using the refresh token received in the X-Refresh-Token header.

## Database
Database stores:
+ token id (the same for access and refresh tokens)
+ bcrypt hash of JWT refresh token sign 
+ status (used, unused, blocked and so on).

## Sending email when the user changes IP

When the IP address changes, the email is sent via Mailtrap.
![img_1.png](img_1.png)