const AWS = require('./libs/awsConfig')
const { getVerifyMiddleware, signUp, signIn, logOut, refresh, verify, changePassword, requestResetPassword, resetPassword } = require('./libs/cognitoAuth')

module.exports = {
    init: AWS.initAWS,
    getVerifyMiddleware,
    signUp,
    signIn,
    logOut,
    refresh,
    verify,
    changePassword,
    requestResetPassword,
    resetPassword
}