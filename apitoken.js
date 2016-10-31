// Add a new function to player sandbox space
// Some Super Secret Secret (32 character hex string)
const secretFile = `${__dirname}/secret.bin`
const fs = require('fs')
try {
  fs.accessSync(secretFile)
} catch(e) {
  fs.writeFileSync(secretFile, require('crypto').randomBytes(16))
}
const secret = fs.readFileSync(secretFile); // Buffer.from('DEADBEEF000000000000000000000000', 'hex')
const jwt = require('./lib/jwt')

module.exports = function (config) {
  if (config.engine) {
    config.engine.onPlayerSandbox = function (sandbox) {
      sandbox.getAPIToken = function () {
        let key = generateToken(sandbox.module.user)
        sandbox.console.log('API KEY:', key)
      }
    }
  }
  if (config.backend) {
    const path = require('path')
    const basicAuth = require('basic-auth')
    const authlib = require(path.join(path.dirname(require.main.filename), '../lib/authlib'))
    config.backend.router.post('/auth/signin', (req, res) => {
      let { email, password } = req.body
      try {
        if (email != 'token') throw new Error('invalid email')
        let data = verifyToken(req.body.password)
        authlib.genToken(data.user)
          .then(token => {
            res.json({ ok: 1, token})
          })
      } catch(e) {
        console.error(e)
        res.status(401).json({ error: 'unauthorized' })
      }
    })
    let preConfig = config.backend.onExpressPreConfig
    config.backend.onExpressPreConfig = function (app) {
      app.post('/user/code', (req, res, next) => {
        let { name, pass } = basicAuth(req)
        try {
          if (name != 'token') return next()
          let data = verifyToken(pass)
          authlib.genToken(data.user)
            .then(token => {
              req.headers['x-token'] = token
              next()
            })
        } catch(e) {
          next()
        }
      })
      return preConfig(app)
    }
  }
}

function sha128 (val) {
  return require('crypto').createHash('sha128').update(val).digest()
}

function generateToken (userid) {
  let data = {
    iat: Date.now(),
    user: userid
  }
  return jwt.encode(data, secret)
}

function verifyToken (token) {
  return jwt.decode(token, secret)
}
