# Go-MongoDB-JWT-Authentication

SImple Authentication Microservice using Go, user data and Blacklisted JWT are save in MongoDB database

Environment Variable Needed:

 | Variable    | Description                                                        |
 | ----------- | ------------------------------------------------------------------ |
 | APP_NAME    | Current app name, not affecting front end, only used for logging   |
 | PORT        | Port which server will listen to, eg: 80                           |
 | DB_URI      | MongoDB URI, eg: mongodb+srv://user:pass@localhost                 |
 | DB_NAME     | Database name where collection is stored                           |
 | JWT_SECRET  | Secret Passphrase for JWT Signing                                  |
 | PREFORK     | Prefork mode for fiber (true/false)                                |
