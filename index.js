const base64url = require('base64url');
const crypto = require('crypto');

let Factory = function (algorithm) {
    let claims;

    let issuer;
    let subject;
    let audience;
    let expiry;

    let setClaims = _claims => {
        // validate claims as a JSON Object and set it
        claims = _claims;

        return instance;
    }

    let setIssuer = _issuer => {
        issuer = _issuer;

        return instance;
    }

    let setSubject = _subject => {
        subject = _subject;

        return instance;
    }

    let setAudience = _audience => {
        audience = _audience;

        return instance;
    }

    let setExpiry = _expiry => {
        expiry = _expiry;

        return instance;
    }

    let sign = key => {
        // generate header

        let header = base64url.encode(JSON.stringify({
            alg: algorithm,
            typ: "JWT"
        }));

        // add recommended claims
        claims['iat'] = Math.floor(new Date() / 1000);

        if (issuer) {
            claims['iss'] = issuer;
        }

        if (subject) {
            claims['sub'] = subject;
        }

        if (audience) {
            claim['aud'] = audience;
        }

        if (expiry) {
            claims['exp'] = claims['iat'] + expiry;
        }

        // generate payload

        let payload = base64url.encode(JSON.stringify(claims));

        // generate signature
        let signature;
        if (algorithm.startsWith('HS')) {
            // HMAC
            let hashAlgo = 'sha' + algorithm.substr(2);
            let data = `${header}.${payload}`;

            signature = hmac(hashAlgo, data, key);
        }
        else {
            console.log('Unknown algorithm');
        }

        // return jws
        return `${header}.${payload}.${signature}`;
    }

    let instance = {
        setIssuer,
        setSubject,
        setAudience,
        setExpiry,
        setClaims,
        sign
    }

    return instance;
}

let Parser = function () {
    let issuer;
    let subject;
    let audience;
    let expiry;

    let validateIssuer = _issuer => {
        issuer = _issuer;

        return instance;
    }

    let validateSubject = _subject => {
        subject = _subject;

        return instance;
    }

    let validateAudience = _audience => {
        audience = _audience;

        return instance;
    }

    let validateExpiry = _expiry => {
        expiry = _expiry;

        return instance;
    }

    let parse = (jwt, key) => {
        let parts = jwt.split('\.');

        let header = JSON.parse(base64url.decode(parts[0]));
        let claims = JSON.parse(base64url.decode(parts[1]));

        if (header && header.alg) {
            let algorithm = header.alg;

            if (algorithm.startsWith('HS')) {
                // HMAC
                let hashAlgo = 'sha' + algorithm.substr(2);
                let data = `${parts[0]}.${parts[1]}`;

                signature = hmac(hashAlgo, data, key);

                if (signature === parts[2]) {
                    // signature is valid

                    // check if expired
                    if (claims && claims.exp && claims.exp < currentTime()) {
                        throw new Error('JWTUtility Parser: Token Expired');
                    }
                    else {
                        if (expiry) {
                            if (claims.iat) {
                                if (currentTime() > claims.iat + expiry) {
                                    throw new Error('JWTUtility Parser: Token Expired');
                                }
                            }
                            else {
                                throw new Error('JWTUtility Parser: "iat" claim is missing');
                            }
                        }
                    }

                    if (issuer && issuer !== claims.iss) {
                        // throw invalid issuer error
                        throw new Error('JWTUtility Parser: Invalid Issuer');
                    }

                    if (audience && audience !== claims.aud) {
                        // throw invalid audience error
                        throw new Error('JWTUtility Parser: Invalid Audience');
                    }

                    if (subject && subject !== claims.sub) {
                        // throw invalid subject error
                        throw new Error('JWTUtility Parser: Invalid Subject');
                    }

                    return {
                        headers: header,
                        claims: claims
                    }
                }
                else {
                    // throw invalid signature error
                    throw new Error('JWTUtility Parser: Invalid Signature');
                }
            }
            else {
                throw new Error('JWTUtility Parser: Invalid Algorithm');
            }
        }
    }

    let instance = {
        parse,
        validateIssuer,
        validateSubject,
        validateAudience,
        validateExpiry
    }

    return instance;
}

function hmac(algorithm, data, key) {
    let hash = crypto.createHmac(algorithm, key)
        .update(data)
        .digest('hex');

    return base64url.encode(hash, 'hex');
}

function currentTime() {
    return Math.floor(new Date() / 1000);
}

module.exports = {
    getFactory: algorithm => {
        // check if algorithm supported

        // return an instance
        return new Factory(algorithm);
    },
    getParser: () => {
        return new Parser();
    }
}