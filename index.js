const { init, getVerifyMiddleware, signUp, signIn, logOut, refresh, verify, changePassword, requestResetPassword, resetPassword } = require('./libs/cognitoAuth')

module.exports = {
    init: init,
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