const express = require('express')
const mongoose = require('mongoose')
const passport = require('passport')
const bodyParser = require('body-parser')
const authRoutes = require('./routes/auth')
const positionRoutes = require('./routes/position')
const analyticsRoutes = require('./routes/analytics')
const categoryRoutes = require('./routes/category')
const orderRoutes = require('./routes/order')
const keys = require('./config/keys')

const app = express()
mongoose
    .connect(keys.mongoURI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        useCreateIndex: true,
    })
    .then(() => console.log('MongoDb connected'))
    .catch(err => console.log(err))

app.use(passport.initialize())
require('./middleware/passport')(passport)

app.use(require('morgan')('dev'))
app.use(require('cors')())
app.use(
    bodyParser.urlencoded({
        extended: true,
    })
)
app.use(bodyParser.json())

app.use('/api/auth', authRoutes)
app.use('/api/position', positionRoutes)
app.use('/api/analitycs', analyticsRoutes)
app.use('/api/category', categoryRoutes)
app.use('/api/order', orderRoutes)

module.exports = app
