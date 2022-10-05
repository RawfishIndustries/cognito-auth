const awsConfig = require('./awsConfig')

const jwkToPem = require('jwk-to-pem')
const axios = require('axios')
const jwt = require('jsonwebtoken')

const logger = require('../../lib/logger')
const { CognitoRefreshToken } = require('amazon-cognito-identity-js')

const TOKEN_USE_ACCESS = 'access'
const TOKEN_USE_ID = 'id'

const MAX_TOKEN_AGE = 60 * 60 // 3600 seconds
const ALLOWED_TOKEN_USES = [TOKEN_USE_ACCESS, TOKEN_USE_ID]
const ISSUER = awsConfig.getIssuer()

const JSONAPIError = require('jsonapi-serializer').Error

// Set custum auth error in jsonapi format
function customError(code, title, message) {
    return new JSONAPIError({
        status: code,
        title: title,
        detail: message
    })
}

// Get the middleware function that will verify the incoming request
function _getVerifyMiddleware (req, res, next) {
    // Fetch the JWKS data used to verify the signature of incoming JWT tokens
    const pemsDownloadProm = _init()
        .catch((err) => {
            // Failed to get the JWKS data - all subsequent auth requests will fail
            logger.error(err)
            return { err }
        })
    return _verifyMiddleWare(pemsDownloadProm, req, res, next)
    
}

// One time initialisation to download the JWK keys and convert to PEM format. Returns a promise.
function _init () {
    return new Promise((resolve, reject) => {
        const config = {
            method: 'GET',
            url: `${ISSUER}/.well-known/jwks.json`,
            json: true
        }

        axios(config).then(response => {
            if (!response.data || !response.data.keys) {
                logger.debug(`JWKS data is not in expected format. Response was: ${JSON.stringify(response)}`)
                reject(new Error('Internal error occurred downloading JWKS data.')) // don't return detailed info to the caller
                return
            }
            const pems = {}
            for (let i = 0; i < response.data.keys.length; i++) {
                pems[response.data.keys[i].kid] = jwkToPem(response.data.keys[i])
            }
            logger.info(`Successfully downloaded ${response.data.keys.length} JWK key(s)`)
            resolve(pems)
        }).catch(err => {
            logger.debug(`Failed to download JWKS data. err: ${err}`)
            reject(new Error('Internal error occurred downloading JWKS data.')) // don't return detailed info to the caller
        })
    })
}

// Verify the Authorization header and call the next middleware handler if appropriate
function _verifyMiddleWare (pemsDownloadProm, req, res, next) {
    pemsDownloadProm.then((pems) => {
        return _verifyProm(pems, req.get('Authorization'))
    })
        .then((decoded) => {
            // Caller is authorised - copy some useful attributes into the req object for later use
            logger.debug(`Valid JWT token. Decoded: ${JSON.stringify(decoded)}.`)
            req.user = {
                sub: decoded.sub,
                token_use: decoded.token_use
            }
            if (decoded.token_use === TOKEN_USE_ACCESS) {
                // access token specific fields
                req.user.scope = decoded.scope.split(' ')
                req.user.username = decoded.username
                req.user.email = decoded.username 
            }
            if (decoded.token_use === TOKEN_USE_ID) {
                // id token specific fields
                req.user.email = decoded.email
                req.user.username = decoded['cognito:username']
            }
            next()
        })
        .catch((err) => {
            res.status(401).send(err)
        })
}

// Verify the Authorization header and return a promise.
function _verifyProm (pems, auth) {
    return new Promise((resolve, reject) => {
        if (pems.err) {
            reject(new Error(pems.err.message || pems.err))
            return
        }

        // Check the format of the auth header string and break out the JWT token part
        if (!auth || auth.length < 10) {
            reject(customError(401, 'Invalid authorization', 'Invalid or missing Authorization header. Expected to be in the format \'Bearer <your_JWT_token>\'.'))
            return
        }
        const authPrefix = auth.substring(0, 7).toLowerCase()
        if (authPrefix !== 'bearer ') {
            reject(customError(401, 'Invalid authorization', 'Authorization header is expected to be in the format \'Bearer <your_JWT_token>\'.'))
            return
        }
        const token = auth.substring(7)

        // Decode the JWT token so we can match it to a key to verify it against
        const decodedNotVerified = jwt.decode(token, { complete: true })
        if (!decodedNotVerified) {
            logger.debug('Invalid JWT token. jwt.decode() failure.')
            reject(customError(401, 'Invalid token', 'Authorization header contains an invalid JWT token.')) // don't return detailed info to the caller
            return
        }
        if (!decodedNotVerified.header.kid || !pems[decodedNotVerified.header.kid]) {
            logger.debug(`Invalid JWT token. Expected a known KID ${JSON.stringify(Object.keys(pems))} but found ${decodedNotVerified.header.kid}.`)
            reject(customError(401, 'Invalid token', 'Authorization header contains an invalid JWT token.')) // don't return detailed info to the caller
            return
        }

        // Now verify the JWT signature matches the relevant key
        jwt.verify(token, pems[decodedNotVerified.header.kid], {
            algorithms: ['RS256'],
            issuer: ISSUER,
            maxAge: MAX_TOKEN_AGE
        },
        function (err, decodedAndVerified) {
            if (err) {
                logger.debug(`Invalid JWT token. jwt.verify() failed: ${err}.`)
                if (err instanceof jwt.TokenExpiredError) {
                    reject(customError(401, 'Expired JWT token', `Authorization header contains a JWT token that expired at ${err.expiredAt.toISOString()}.`))
                } else {
                    reject(customError(401, 'Invalid token','Authorization header contains an invalid JWT token.')) // don't return detailed info to the caller
                }
                return
            }

            // The signature matches so we know the JWT token came from our Cognito instance, now just verify the remaining claims in the token

            // Verify the token_use matches what we've been configured to allow
            if (ALLOWED_TOKEN_USES.indexOf(decodedAndVerified.token_use) === -1) {
                logger.debug(`Invalid JWT token. Expected token_use to be ${JSON.stringify(ALLOWED_TOKEN_USES)} but found ${decodedAndVerified.token_use}.`)
                reject(customError(401, 'Invalid token', 'Authorization header contains an invalid JWT token.')) // don't return detailed info to the caller
                return
            }

            // Verify the client id matches what we expect. Will be in either the aud or the client_id claim depending on whether it's an id or access token.
            const clientId = (decodedAndVerified.aud || decodedAndVerified.client_id)
            if (clientId !== awsConfig.getClientId()) {
                logger.debug(`Invalid JWT token. Expected client id to be ${awsConfig.getClientId()} but found ${clientId}.`)
                reject(customError(401, 'Invalid token', 'Authorization header contains an invalid JWT token.')) // don't return detailed info to the caller
                return
            }

            // Done - all JWT token claims can now be trusted
            return resolve(decodedAndVerified)
        })
    })
}

// Signin function to retrive JWT token
function _signIn(email, password) {
    return new Promise((resolve) => {
        awsConfig.getCognitoUser(email).authenticateUser(awsConfig.getAuthDetails(email, password), {
            onSuccess: (result) => {
                const token = {
                    accessToken: result.getAccessToken().getJwtToken(),
                    idToken: result.getIdToken().getJwtToken(),
                    refreshToken: result.getRefreshToken().getToken(),
                }  
                return resolve({ statusCode: 200, response: awsConfig.decodeJWTToken(token) })
            },
        
            onFailure: (err) => {
                return resolve(customError(401, 'Unauthorized', 'Incorrect username or password.'))
            },
        })
    })
}

function _signUp(email, password, agent = 'none') {
    return new Promise((resolve) => {
        awsConfig.initAWS ()
        awsConfig.setCognitoAttributeList(email,agent)
        awsConfig.getUserPool().signUp(email, password, awsConfig.getCognitoAttributeList(), null, function(err, result){
            if (err) {
                return resolve({ statusCode: 422, response: err })
            }
            const response = {
                username: result.user.username,
                userConfirmed: result.userConfirmed,
                userAgent: result.user.client.userAgent,
                userSub: result.userSub
            }
            return resolve({ statusCode: 201, response: response })
        })
    })
}

function _changePassword(oldPassword, newPassword) {
    return new Promise((resolve) => {
        awsConfig.initAWS ()
        const authUser = awsConfig.getUserPool().getCurrentUser()
        if(!authUser) {
            return resolve({ statusCode: 422, response: 'User is not authenticated' })
        }
        authUser.getSession((err, session) => {
            if(err) {
                return resolve({ statusCode: 422, response: err })
            }
            authUser.changePassword(oldPassword, newPassword, (err, result) => {
                if(err) {
                    return resolve({ statusCode: 422, response: err })
                }
                return resolve({ statusCode: 201, response: result })
            })
        })
    })
}

function _requestResetPassword(email) {
    return new Promise((resolve) => {
        awsConfig.initAWS ()
        const cognitoUser = awsConfig.getCognitoUser(email)
        if(!cognitoUser) {
            return resolve({ statusCode: 422, response: 'User not exist' })
        }

        cognitoUser.forgotPassword({
            onSuccess: (result) => {
                return resolve({ statusCode: 200, response: result })
            },
    
            onFailure: (err) => {
                return resolve({ statusCode: 422, response: err })
            }
        })
    })
}

function _resetPassword(email, confirmation_code, newPassword) {
    return new Promise((resolve) => {
        awsConfig.initAWS ()
        const cognitoUser = awsConfig.getCognitoUser(email)
        if(!cognitoUser) {
            return resolve({ statusCode: 422, response: 'User not exist' })
        }

        cognitoUser.confirmPassword(confirmation_code, newPassword,{
            onSuccess: (result) => {
                return resolve({ statusCode: 201, response: result })
            },
            onFailure: (err) => {
                return resolve({ statusCode: 422, response: err })
            }
        })
    })
}

function _verify(email, code) {
    return new Promise((resolve) => {
        awsConfig.getCognitoUser(email).confirmRegistration(code, true, (err, result) => {
            if (err) {
                return resolve({ statusCode: 422, response: err })
            }
            return resolve({ statusCode: 400, response: result })
        })
    })
}

function _refresh(refreshToken, email) {
    return new Promise((resolve) => {
        awsConfig.initAWS ()
        const token = new CognitoRefreshToken({ RefreshToken: refreshToken})
        awsConfig.getCognitoUser(email).refreshSession(token, function(err, result){
            if (err) {
                return resolve({ statusCode: 422, response: err })
            }
            const token = {
                accessToken: result.getAccessToken().getJwtToken(),
                idToken: result.getIdToken().getJwtToken(),
                refreshToken: result.getRefreshToken().getToken(),
            }  
            return resolve({ statusCode: 200, response: awsConfig.decodeJWTToken(token) })
        })
    })
}

function _logOut(email) {
    return new Promise((resolve) => {
        awsConfig.initAWS ()
        awsConfig.getCognitoUser(email).signOut(function(err, result){
            if (err) {
                return resolve({ statusCode: 422, response: err })
            }
            return resolve()
        })
    })
}

exports.getVerifyMiddleware = _getVerifyMiddleware
exports.signIn = _signIn
exports.signUp = _signUp
exports.logOut = _logOut
exports.refresh = _refresh
exports.verify = _verify
exports.changePassword = _changePassword
exports.requestResetPassword = _requestResetPassword
exports.resetPassword = _resetPassword