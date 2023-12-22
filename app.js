//jshint esversion:6
require('dotenv').config();// this is file which stores secret info in terms of environment variables.
const express=require('express');
const bodyParser=require('body-parser');
const ejs=require('ejs');
//const md5 = require('md5');//use for hashing the passwords when user login with email and username we can only see email and password will be converted into hash
//const encrypt = require('mongoose-encryption');

const bcrypt = require('bcrypt');// it adds a new salt(random value) that is stored with hash inside database to provide more security. bcz same password will generate same hash but we are not getting same salt for same hash.
const saltRounds = 10;

console.log(process.env.API_KEY);//for understanding .env

const mongoose=require('mongoose');

const app=express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended:true
}));

mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser:true},{useUnifiedTopology: true});

const userSchema = new mongoose.Schema({
    email:String,
    password:String
});


//userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptionFields:["password"] });

const User= new mongoose.model("User",userSchema);

app.get("/",function(req,res){
    res.render("home");
})
app.get("/login",function(req,res){
    res.render("login");
})
app.get("/register",function(req,res){
    res.render("register");
})

app.post("/register",function(req,res){

    bcrypt.hash(req.body.password, saltRounds, function(err,hash){// this function converts password to hash by adding saltRounds
        const newUser= new User({
            email:req.body.username,
            password:hash
        });
        newUser.save(function(err){
            if(err){
                console.log(err);
            }
            else{
                res.render("secrets");//unless user completes registration he wont able to see the secrets route.
            }
        });
    });
});

app.post("/login",function(req,res){
    const username = req.body.username;
    // const password = md5(req.body.password);
    const password = (req.body.password);

    User.findOne({email:username},function(err,foundUser){
        if(err){
            console.log(err);
        }
        else{
            if(foundUser){
                bcrypt.compare(password, foundUser.password, function(err,result){//when user login it checks password entered by user with pasword which was entered by user at the time of registration which is stored in database along with hash and salt if both matches then user will be permitted to see secrets route.
                    if(result == true){
                        res.render("secrets");
                    }
                });
                   
            }
        }
    })
})

app.listen(3000,function(){
    console.log("server started at port 3000")
})