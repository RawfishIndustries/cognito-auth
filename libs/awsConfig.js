const AWS = require('aws-sdk')
const jwt = require('jsonwebtoken')
const AmazonCognitoIdentity = require('amazon-cognito-identity-js')
let cognitoAttributeList = []

class AWSConfig {
    
    constructor (region, identityPoolId, userPoolId, clientId) {
        AWS.config.region = region // Region
        AWS.config.credentials = new AWS.CognitoIdentityCredentials({
            IdentityPoolId: identityPoolId,
        })
        this.poolData = { 
            UserPoolId: userPoolId,
            ClientId: clientId,
        }
        this.issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`
        this.cognitoIdentityServiceProvider = new AWS.CognitoIdentityServiceProvider
    }

    attributes(key, value) { 
        return {
            Name: key,
            Value: value
        }
    }
  
    setCognitoAttributeList(email, agent) {
        let attributeList = []
        attributeList.push(this.attributes('email',email))
        attributeList.forEach(element => {
            cognitoAttributeList.push(new AmazonCognitoIdentity.CognitoUserAttribute(element))
        })
    }
  
    getCognitoAttributeList() {
        return cognitoAttributeList
    }
  
    getCognitoUser(email) {
        const userData = {
            Username: email,
            Pool: this.getUserPool()
        }
        return new AmazonCognitoIdentity.CognitoUser(userData)
    }

    getUserPool(){
        return new AmazonCognitoIdentity.CognitoUserPool(this.poolData)
    }

    getAuthDetails(email, password) {
        let authenticationData = {
            Username: email,
            Password: password,
        }
        return new AmazonCognitoIdentity.AuthenticationDetails(authenticationData)
    }

    getIssuer() {
        return this.issuer
    }

    getClientId() {
        return this.poolData.ClientId
    }

    disableUser(cognitoSub) {
        return this.cognitoIdentityServiceProvider.adminDisableUser({ UserPoolId: this.poolData.UserPoolId, Username: cognitoSub }).promise()
    }

    enableUser(cognitoSub) {
        return this.cognitoIdentityServiceProvider.adminEnableUser({ UserPoolId: this.poolData.UserPoolId, Username: cognitoSub }).promise()
    }

    decodeJWTToken(token) {
        const {  email, exp, auth_time , token_use, sub} = jwt.decode(token.idToken)
        return {  token, email, exp, uid: sub, auth_time, token_use }
    }
}
module.exports = AWSConfig
