const AWS = require('aws-sdk')
const jwt = require('jsonwebtoken')
const AmazonCognitoIdentity = require('amazon-cognito-identity-js')
let cognitoAttributeList = []

let poolData
let issuer 
function initAWS (region, identityPoolId, userPoolId, clientId) {
    AWS.config.region = region // Region
    AWS.config.credentials = new AWS.CognitoIdentityCredentials({
        IdentityPoolId: identityPoolId,
    })
    poolData = { 
        UserPoolId: userPoolId,
        ClientId: clientId,
    }
    issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`
}

const attributes = (key, value) => { 
    return {
        Name: key,
        Value: value
    }
}
  
function setCognitoAttributeList(email, agent) {
    let attributeList = []
    attributeList.push(attributes('email',email))
    attributeList.forEach(element => {
        cognitoAttributeList.push(new AmazonCognitoIdentity.CognitoUserAttribute(element))
    })
}
  
function getCognitoAttributeList() {
    return cognitoAttributeList
}
  
function getCognitoUser(email) {
    const userData = {
        Username: email,
        Pool: getUserPool()
    }
    return new AmazonCognitoIdentity.CognitoUser(userData)
}

function getUserPool(){
    return new AmazonCognitoIdentity.CognitoUserPool(poolData)
}

function getAuthDetails(email, password) {
    let authenticationData = {
        Username: email,
        Password: password,
    }
    return new AmazonCognitoIdentity.AuthenticationDetails(authenticationData)
}

function getIssuer() {
    return this.issuer
}

function getClientId() {
    return this.poolData.ClientId
}

function decodeJWTToken(token) {
    const {  email, exp, auth_time , token_use, sub} = jwt.decode(token.idToken)
    return {  token, email, exp, uid: sub, auth_time, token_use }
}

module.exports = {
    initAWS,
    getCognitoAttributeList,
    getUserPool,
    getCognitoUser,
    setCognitoAttributeList,
    getAuthDetails,
    getIssuer,
    getClientId,
    decodeJWTToken,
}
