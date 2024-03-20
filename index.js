const { init, getVerifyMiddleware, signUp, signIn, addToGroup, logOut, enableUser, disableUser, refresh, verify, changePassword, requestResetPassword, resetPassword } = require('./libs/cognitoAuth')

module.exports = {
    init: init,
    getVerifyMiddleware,
    signUp,
    signIn,
    addToGroup,
    logOut,
    enableUser,
    disableUser,
    refresh,
    verify,
    changePassword,
    requestResetPassword,
    resetPassword
}