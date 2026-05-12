require('dotenv').config();

const express = require('express');
const session = require('express-session');
const joi = require('joi');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const app = express();

const PORT = process.env.PORT || 3000;

const expireTime = 60 * 60 * 1000;

app.set("view engine", "ejs");

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_user_database = process.env.MONGODB_USER_DATABASE;
const mongodb_session_database = process.env.MONGODB_SESSION_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

const { database } = require('./databaseConnection');
const userCollection = database.db(mongodb_user_database).collection('users');

app.use(express.urlencoded({extended: false}));
app.use(express.json());

app.use(express.static(__dirname + "/public"));

const { MongoClient } = require("mongodb");

const uri = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/?retryWrites=true&w=majority`;

const client = new MongoClient(uri);

const mongoStore = MongoStore.create({
    client: client,
    dbName: mongodb_session_database
});

mongoStore.on('error', (err) => {
    console.error('MongoStore error:', err);
});

app.use(session({ 
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: false,
    cookie: { maxAge: expireTime }
}));

app.get('/', (req, res) => {
    if (!req.session.authenticated){
        res.render('mainPage');
    } else {
        res.render('loggedInMain', {username: req.session.name});
    }
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/loggingin', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = joi.object({
        email: joi.string().email().required(),
        password: joi.string().max(20).required()
    }); 

    const validationResult = schema.validate({ email, password });

    if (validationResult.error) {
        res.render('invalidLogin', {issue: 'Invalid Input.'});
        return;
    }

	const result = await userCollection.find({email: email}).toArray();

	if (result.length != 1) {
		res.render('invalidLogin', {issue: 'User Not Found.'});
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		req.session.authenticated = true;
        req.session.name = result[0].username;
        req.session.status = result[0].status;
		req.session.save(() => {
            res.redirect('/members');
        });
		return;
	}
	else {
		res.render('invalidLogin', {issue: 'Incorrect Password.'});
		return;
	}
});

app.get('/signup', (req, res) => {
    res.render('signup');
});

app.post('/submitUser', async (req, res) => {

    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    if (!username) {
        return res.render('signupError', {error: 'provide a username'});
    }
    if (!email) {
        return res.render('signupError', {error: 'provide an email'});
    }
    if (!password) {
        return res.render('signupError', {error: 'provide a password'});
    }

    const schema = joi.object({
		username: joi.string().alphanum().max(20).required(),
		password: joi.string().max(20).required(),
        email: joi.string().email().required()
	});

    const validationResult = schema.validate({username, password, email});

	if (validationResult.error != null) {
        return res.render('signupError', {error: 'enter valid user info'});
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({username: username, email:email, password: hashedPassword, status: 'user'});

    req.session.authenticated = true;
    req.session.name = username;

    req.session.save(() => {
        res.redirect('/members');
    });
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
        return;
    }
    const images = ['image1.png', 'image2.png', 'image3.png'];
    const random = images[Math.floor(Math.random() * images.length)];
    res.render('members', {name: req.session.name, random: random});
});

app.get('/admin', async (req, res) => {
    if (!req.session.authenticated){
        res.redirect('/login');
        return;
    }
    if (req.session.status == 'admin'){
        const users = await userCollection.find({}).toArray();
        res.render('admin', {users});
    }else{
        res.status(403);
        res.render('forbidden');
    }
});

app.post('/makeadmin', async (req, res) => {
    const username = req.body.username;

    await userCollection.updateOne(
        {username: username},
        {$set: {status:'admin'}}
    );
    res.redirect('/admin');
});

app.post('/makeuser', async (req, res) => {
    const username = req.body.username;

    await userCollection.updateOne(
        {username: username},
        {$set: {status:'user'}}
    );
    res.redirect('/admin');
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.use((req,res) => {
	res.status(404);
	res.render('pageNotFound');
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});