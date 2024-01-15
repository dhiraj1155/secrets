//jshint esversion:6
require('dotenv').config();// this is file which stores secret info in terms of environment variables.
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const session = require('express-session');
const passport = require("passport");//Passport is Express-compatible authentication middleware for Node.js.let you use different services with single set of credentials.
const passportLocalMongoose = require("passport-local-mongoose");// used for user authentication
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findOrCreate');

const mongoose = require('mongoose');

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended:true
}));

app.use(session({
    secret:"our little secret",
    resave: false,
    saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser:true},{useUnifiedTopology: true});
mongoose.set("useCreateIndex",true);

const userSchema = new mongoose.Schema({
    email:String,
    password:String,
    googleId : String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User",userSchema);

passport.use(User.createStrategy());
// serializeUser
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
  });
  // DeserializeUser
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

// Configuring a new Google OAuth strategy for Passport
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  // Callback function executed upon successful Google authentication
  function(accessToken, refreshToken, profile, cb) {
    // Logging user information associated with Gmail to the terminal
    console.log(profile);

    // Using Mongoose's findOrCreate method to search for an existing user or create a new one
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      // Returning the callback function with potential errors and the user object
      return cb(err, user);
    });
  }
));


app.get("/",function(req,res){
    res.render("home");
})


app.get("/auth/google",
    // Initiating Google OAuth authentication using Passport middleware
    passport.authenticate("google", {scope: ["profile"]})
);

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

app.get("/login",function(req,res){
    res.render("login");
})
app.get("/register",function(req,res){
    res.render("register");
})

// Handling GET requests to the "/secrets" route
app.get("/secrets", function(req, res) {
    // Using Mongoose to find users with a non-null "secret" field in the database
    User.find({"secret":{$ne: null}}, function(err, foundUsers) {
        if (err) {
            // If there's an error during the database query, log it to the console
            console.log(err);
        }
        if (foundUsers) {
            // If users with non-null "secret" field are found, render the "secrets" view
            // Pass the foundUsers array to the view for displaying user secrets
            res.render("secrets", {usersWithSecrets: foundUsers});
        }
    });
});


app.get("/logout", function(req, res, next){
    
    req.logout(function(err){
        if(err){return next(err);}
        res.redirect("/");
    });
   
});

app.post("/register",function(req,res){

    User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err){
            console.log(err);
            res.redirect("/register");
        }
        else{
            passport.authenticate("local")(req,res, function(){
                res.redirect("/secrets")
            })
        }
    })
  
});

app.post("/login",function(req,res){
   const user = new User({
    username: req.body.username,
    password: req.body.password
   });

   req.login(user, function(err){
    if(err){
        console.log(err);
    }else{
        passport.authenticate("local")(req, res, function(){
            res.redirect("/secrets");
        });
       
    }
   })
})
app.get("/submit",function(req,res){
    if(req.isAuthenticated()){
        res.render("submit");
    }
    else{
        res.redirect("/login");
    }
});

app.post("/submit",function(req,res){
    const submittedSecret = req.body.secret;

    User.findById(req.user.id, function(err,foundUser){
        if(err){
            console.log(err);
        }else{
            if(foundUser){
                foundUser.secret = submittedSecret;
                foundUser.save(()=>{
                    res.redirect("/secrets");  
                });
                
            }
        }
    })
})
app.listen(3000,function(){
    console.log("server started at port 3000")
})