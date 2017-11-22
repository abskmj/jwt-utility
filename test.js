const JWTUtility = require('./index');

let jwt = JWTUtility.getFactory('HS256')
    .setIssuer('majhi')
    .setSubject('Login')
    .setExpiry(10)
    .setClaims({
        user: 'testUser',
        name: 'Test User'
    })
    .sign('testKy');

console.log(jwt);

let data = JWTUtility.getParser()
    .validateIssuer('majhi')
    .validateExpiry(10)
    .validateSubject('Login')
    .parse(jwt, 'testKy');

console.log(data);