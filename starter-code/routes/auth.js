const express = require('express')
const bcryptjs = require('bcryptjs')
const User = require('../models/user')
const router = express.Router()
const zxcvbn = require('zxcvbn')

router.get('/register', (req, res, next) => {
    res.render('auth/register')
})

router.post('/register', (req, res, next) => {
    const { username, password } = req.body
    const salt = bcryptjs.genSaltSync()
    const hashPassword = bcryptjs.hashSync(password, salt)

    if (username === '' || password === '') {
        res.render('auth/register', {
            errorMessage: 'You need a username and a password to register'
        })
        return
    }

    User.findOne({ username })
        .then(user => {
            if (user) {
                console.log('Username taken: ', user.username)
                res.render('auth/register', {
                    errorMessage: 'There is already a registered user with this username'
                })
                return
            }
            User.create({ username, password: hashPassword })
                .then(() => {
                    res.redirect('/secret')
                })
                .catch(err => {
                    console.error('Error while creating user', err)
                })
        })
        .catch(err => {
            console.error('Error while looking for user', err)
        })
})

router.get('/login', (req, res, next) => {
    res.render('auth/login')
})

router.post('/login', (req, res, next) => {
    const { username, password } = req.body
    if (username === '' || password === '') {
        res.render('auth/login', {
            errorMessage: 'This username was not found'
        })
        return
    }

    User.findOne({ username })
        .then(user => {
            if (!user) {
                res.render('auth/login', {
                    errorMessage: 'This username was not found'
                })
            }
            if (bcryptjs.compareSync(password, user.password)) {
                //Add loggedInUser key to the req.session object
                req.session.loggedInUser = user
                res.redirect('/secret')
            } else {
                res.render('auth/login', {
                    errorMessage: 'Wrong password'
                })
            }
        })
        .catch(err => {
            console.error('Error while finding user', err)
        })
})

router.get('/secret', (req, res, next) => {
    if (req.session.loggedInUser) {
        res.render('auth/secret')
    } else {
        res.render('error')
    }
})

router.get('/main', (req, res, next) => {
    res.render('auth/main')
})

module.exports = router
