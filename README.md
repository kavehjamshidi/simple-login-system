# simple-login-system
A simple token-based authentication and authorization system using Nodejs, Express, MongoDB, Redis, bcrypt, and JWT.  
For authentication, access token and refresh token strategy is used. Access tokens are valid for only five minutes while refresh tokens are valid for seven days. User can retrieve new access and refresh tokens using the existing refresh token. The old refresh token is stored in a redis cache as blacklisted till it is expired.  
Password reset functionality is available through sending a unique password reset URL to user's email. 

## Using this repo

### Clone

```bash
$ git clone git@github.com:kavehjamshidi/simple-login-system.git
$ cd simple-login-system
```

### Installing the dependencies

```bash
$ npm install
```  
Installing the devevelopent dependencies used for **testing** and **linting**:  
```bash
$ npm install --only=dev
```
### Setting up environment variables

Currently **ten** environment variables are required.

- PORT: Port number
- JWT_SECRET: A string used for signing JWTs. It is better for this string to be long (e.g. 32 characters).
- DB_URI: [MongoDB connection URI](https://docs.mongodb.com/manual/reference/connection-string/).
- REDIS_URI: Redis connection string.
- LOG_FILE_NAME: Name of the file used by logger for logging errors and certain events.  
In this project, SMTP is used for sending password reset emails, requiring a host, port, username, and password. The environment variables listed below are used for this purpose:  
- EMAIL_HOST: Host of the SMTP service (e.g. `smtp.mailtrap.io`).  
- EMAIL_PORT: Port number for the SMTP.
- EMAIL_USERNAME: Username for the SMTP.
- EMAIL_PASSWORD: Password for the SMTP.

These environment variable could be set at OS level or be placed in a .env file located at the root of the project (not recommended).

### Running the project

```bash
$ npm start
```
### Running unit and integration tests  

```bash
$ npm test
```
