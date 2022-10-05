const winston = require('winston')

const levels = {
    error: 0,
    warn: 1,
    info: 2,
    http: 3,
    debug: 4,
}
  
const level = () => {
    // const env = process.env.NODE_ENV || 'development'
    // const isDevelopment = env === 'development'
    // return isDevelopment ? 'debug' : 'warn'
    return 'debug'
}
  
const colors = {
    error: 'red',
    warn: 'yellow',
    info: 'green',
    http: 'magenta',
    debug: 'white',
}
  
winston.addColors(colors)
  
const format = winston.format.combine(
    winston.format.timestamp({
        format: 'YYYY-MM-DD hh:mm:ss'
    }),
    winston.format.splat(),
    winston.format.simple(),
    winston.format.printf(
        info => `${info.timestamp}  ${info.level} : ${info.message}`
    )
)
  
const transports = [
    new winston.transports.Console({
        format: winston.format.combine(winston.format.colorize({all: true}), format)
    }),
    new winston.transports.File({
        format: winston.format.combine(winston.format.uncolorize(), format),
        filename: 'logs/error.log',
        level: 'error',
        maxsize: 10000000
    }),
    new winston.transports.File({
        format: winston.format.combine(winston.format.uncolorize(), format),
        filename: 'logs/all.log',
        maxsize: 10000000,

    })
]
  
const logger = winston.createLogger({
    level: level(),
    levels,
    format,
    transports,
})
  
module.exports = logger
module.exports.stream = {
    write: function(message){
        logger.http(message)
    }
}