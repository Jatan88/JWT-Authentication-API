const express = require('express'); // require express
const app = express();
const auth = require('./middleware/auth') // import auth.js
const User = require('./model/user') // import user.js


require("dotenv").config(); // import .env file
require("./config/database").connect(); // for connecting database


const bcrypt = require('bcryptjs'); // require bcrypt package
const jwt = require('jsonwebtoken'); // require jsw token package
const cookieParser = require('cookie-parser') // require cookie-parser package


app.use(express.json()); // to show json files
app.use(cookieParser()); // for using cookies

app.get('/', (req, res) => {
    res.send("<h1>Hello from auth system - Jatan</h1>")
});

app.post("/register", async (req, res) => {
   try {
    const {firstname, lastname, email, password} = req.body;

    if(!(email && password && firstname && lastname)){
        res.status(400).send("All fields are required");
    }

    const existingUser = await User.findOne({email});

    if(existingUser){
        res.status(401).send("User is already registered");
    }

    const myEncPassword = await bcrypt.hash(password, 10)
    
    const user  = await User.create({
        firstname,
        lastname,
        email: email.toLowerCase(),
        password: myEncPassword,
    });

    // token
    const token = jwt.sign(
        {user_id: user._id, email},
        process.env.SECRET_KEY, 
        {
            expiresIn: "2h"
        }
    )
    user.token = token;

    // update or not in database
    // handle password situation
    user.password = undefined

    // send token or send just success yes and redirect - choice
    res.status(201).json(user)

   }catch(error) {
       console.log(error);
   }

});

app.post("/login", async(req, res) => {
    try{
        const {email, password} = req.body

        if(!(email && password)){
            res.status(400).send("Field is missing")
        }

        const user = await User.findOne({email})

        // if(!user){
        //     res.status(400).send("You are not registered in our app")
        // }

        if(user && (await bcrypt.compare(password, user.password))){
            const token = jwt.sign(
                {user_id: user._id, email},
                process.env.SECRET_KEY,
                {
                    expiresIn: "2h"
                }
            )
            user.token = token;
            user.password = undefined;
            // res.status(200).json(user)

            // if you want to use cookies
            const options = {
                expires: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
                httpOnly: true,
            };
            res.status(200).cookie('token', token, options).json(
                {
                    success: true,
                    token,
                    user
                }
            )
        }

    
        res.send(400).send("email or password is incorrect")

    }catch(error){
        console.log(error);
    }
});

app.get("/dashboard", auth,  (req, res) => {
    res.send("Welcome to secret information");
});

app.get("/logout", (req, res) => {
    res.clearCookie("token");
    res.json({
        message: "cookies expired successfully",
    })
});

module.exports = app;