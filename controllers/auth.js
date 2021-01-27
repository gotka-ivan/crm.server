const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const User = require('../models/User')
const keys = require('../config/keys')
const errorHandler = require('../utils/errorHandler')

module.exports.login = async function (req, res) {
  console.log(req.body)
  const candidate = await User.findOne({ email: req.body.email })
  if (candidate) {
    const passwordResult = bcrypt.compareSync(req.body.password, candidate.password)
    if (passwordResult) {
      const token = getToken(candidate.email, candidate._id)
      res.status(200).json({
        user: {
          name: candidate.name,
          email: candidate.email,
        },
        token: formateToken(token),
      })
    } else {
      res.status(401).json({
        message: ' Пароли не совпадают. Попробуйте снова.',
      })
    }
  } else {
    res.status(404).json({
      message: 'Пользователь с таким email не найден',
    })
  }
}

module.exports.register = async function (req, res) {
  const candidate = await User.findOne({ email: req.body.email })
  if (candidate) {
    res.status(409).json({
      message: 'Такой email уже занят',
    })
  } else {
    const salt = bcrypt.genSaltSync(10)
    const password = req.body.password
    const user = new User({
      name: req.body.name,
      email: req.body.email,
      password: bcrypt.hashSync(password, salt),
    })
    try {
      await user.save()
      const token = getToken(user.email, user._id)
      res.status(201).json({
        user: {
          name: user.name,
          email: user.email,
        },
        token: formateToken(token),
      })
    } catch (err) {
      errorHandler(res, err)
    }
  }
}

getToken = function (email, id) {
  return jwt.sign(
    {
      email,
      userId: id,
    },
    keys.jwt,
    { expiresIn: 60 * 60 }
  )
}

formateToken = function (token) {
  return `Bearer ${token}`
}
