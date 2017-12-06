const JWTUtility = require('./index');

let jwt = JWTUtility.getFactory('HS256')
    .setIssuer('AuthServer')
    .setSubject('Login')
    .setExpiry(10)
    .setClaims({
        user: 'testUser',
        name: 'Test User'
    })
    .sign('secret key');

console.log(jwt);

let data = JWTUtility.getParser()
    .validateIssuer('AuthServer')
    .validateSubject('Login')
    .parse(jwt, 'secret key');

console.log(data);