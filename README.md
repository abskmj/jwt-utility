# JWT Utility for Node.js

This utility can be used to generate and parse [JWTs (JSON Web Tokens)](https://jwt.io/introduction/).

# Supported Algorithms
- HS256
- HS384
- HS512

# Utlity Methods
| Method | Arguments | Description |
| :--- | :--- | :--- |
| `getFactory` | String | Set algorithm to be used to generate the JWT and returns an instance of `Factory` |
| `getParser` |  | Returns an instance of `Parser` which can be used to parse and verify a JWT |

# Generating a Token
```javascript
const JWTUtility = require('@abskmj/jwt-utility');

let jwt = JWTUtility.getFactory('HS256')
    .setIssuer('AuthServer')
    .setSubject('Login')
    .setExpiry(10)
    .setClaims({
        user: 'testUser',
        name: 'Test User'
    })
    .sign('secret key');
```

## Factory Instance Methods
| Method | Arguments | Description |
| :--- | :--- | :--- |
| `setIssuer` | String | Set `iss` claim value. |
| `setSubject` | String | Set `sub` claim value. |
| `setAudience` | String | Set `aud` claim value. |
| `setExpiry` | Number | Set `exp` claim value, value will be current epoch time in seconds + seconds passed as argument. |
| `setClaims` | JSON | Set the custom data that will be part of the JWT. |
| `sign` | String | Generate the JWT using the secret key passed |

# Parsing a Token
```javascript
const JWTUtility = require('@abskmj/jwt-utility');

let data = JWTUtility.getParser()
    .validateIssuer('AuthServer')
    .validateSubject('Login')
    .parse(jwt, 'secret key');
```

## Factory Instance Methods
| Method | Arguments | Description |
| :--- | :--- | :--- |
| `validateIssuer` | String | Validate `iss` claim value. |
| `validateSubject` | String | Validate `sub` claim value. |
| `validateAudience` | String | Validate `aud` claim value. |
| `validateExpiry` | Number | Validate `exp` claim value, value validated against current epoch time in seconds + seconds passed as argument. |
| `parse` | String, String | Set JWT token and key used to verify the token |
