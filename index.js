const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');
const session = require('express-session')



const server = express();

//get session 
const sessionConfig = {
    name: 'notsession', // default is connect.sid
    secret: 'keep this a secret',
    cookie: {
        httpOnly: true,
        maxAge: 1000 * 60 * 2,
        secure: false,
    },
    resave: false,
    saveUninitialized: true,

}

server.use(session(sessionConfig));
server.use(helmet());
server.use(express.json());
server.use(cors());



server.get('/', (req, res) => {
    res.send('Server is alive')
})

// POST	/api/register

server.post('/api/register', (req, res) => {
    let user = req.body;
    const hash = bcrypt.hashSync(user.password, 4)
    user.password = hash

    Users.add(user)
        .then(saved => {
            res.status(201).json(saved);
        })
        .catch(error => {
            res.status(500).json(error);
        });
});

// POST / api / login
server.post('/api/login', (req, res) => {
    let { username, password } = req.body;

    Users.findBy({ username })
        .first()
        .then(user => {
            if (user && bcrypt.compareSync(password, user.password)) {
                //the cookie is sent by the express-session library
                req.session.username = user.username;

                res.status(200).json({ message: `Welcome ${user.username}!` });
            } else {
                res.status(401).json({ message: 'Invalid Credentials' });
            }
        })
        .catch(error => {
            res.status(500).json(error);
        });
});

// implement log out end point.

server.get('/logout', (req, res) => {
    if(req.session) {
        req.session.destroy( err => {
            if(err) {
                res.send('there was an error')
            } else {
                res.send('bye')
            }
        });
    } else {
        res.end();
    }
});

// GET / api / users
function restricted(req, res, next) {
    const {username, password } = req.headers;

    if (username && password) {
        User.findBy({ username })
            .first()
            .then(user => {
                // check if the passwords match
                if (user && bcrypt.compareSync(password, user.password)) {
                    next();
                } else {
                    res.status(401).json({ message: 'Invalid Credentials' });
                }
            })
            .catch( error => {
                res.status(500).json({ message: 'Ran into an unexpected error' });
            })
    } else {
        res.status(400).json({ message: 'No credentials provided'})
    }
}

server.get('/api/users', restricted, (req, res) => {
    User.find()
        .then(users => {
            res.json(users);
        })
        .catch(err => res.send(err));
});

server.listen(9090, () => {
    console.log('Server is listening on port: 9000')
});