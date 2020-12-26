# simple-login-system
A simple token-based authentication and authorization system using Nodejs, Express, MongoDB, bcrypt, and JWT.  
Password reset functionality is available through email. JWTs are sent via secure httpOnly Cookies to the client. 

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
- JWT_EXPIRATION: Used for setting JWT expiration date. More info on [JWT readme](https://github.com/auth0/node-jsonwebtoken).
- JWT_COOKIE_EXPIRATION: A number indicating the number of days the Cookie containing JWT is valid.  
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
