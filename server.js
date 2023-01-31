require('dotenv').config();
const express = require('express'); 
const bodyParser = require('body-parser');
const ejs = require('ejs'); 
const mongoose = require('mongoose');
mongoose.set('strictQuery', true);
const session = require('express-session');
const passport = require('passport');
const passportLocalMonogoose =  require('passport-local-mongoose');
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findeOrCreate = require("mongoose-findorcreate");

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.set('view engine','ejs');
app.use(express.static('public'));

app.use(session({
    secret: 'Our little secret',
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

function connectDB(){
    try {
        // Connect to MongoDB
    //    mongoose.connect("mongodb://127.0.0.1/userDB", { useNewUrlParser: true });
      mongoose.connect(process.env.MONGO_URI);
        console.log('Connection to MongoDB succeeded');
      } catch(err) {
          console.log('Error: Connection to MongoDB failed: ' + err);
        
        }
      }
connectDB();

const userID = new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    facebookId:String,
    secret :String
});

userID.plugin(passportLocalMonogoose); 
userID.plugin(findeOrCreate);
const User = mongoose.model('User',userID);

passport.use(User.createStrategy()); 
passport.serializeUser((user,done)=>{
    done(null ,user.id); 
}); 
passport.deserializeUser((id, done)=>{
    User.findById(id , (err,user)=>{
        done(err,user);
    });
}); 

//GoogleStrategy
passport.use(new GoogleStrategy({
    clientID : process.env.Client_ID , 
    clientSecret : process.env.Client_secret, 
    callbackURL : "http://localhost:3000/auth/google/secrets",
   
},
    function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

//FacebookStrategy
passport.use(new FacebookStrategy({
    clientID: process.env.Facebook_id,
    clientSecret: process.env.Facebook_secret,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
app.get("/",(req,res)=>{
    res.render('home');
});

app.get("/register",(req,res)=>{
    res.render('register');
});

//Google Authenticator
app.get("/auth/google/", passport.authenticate("google", { scope : ["profile"] }));
  
app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

//Facebook Authenticator
  app.get('/auth/facebook',passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });
app.get("/secrets",(req,res)=>{
   User.find({"secret" : {$ne:null}}, (err,foundUser)=>{
      if(err) {
        console.log(err);
      }else{
        if(foundUser){
            res.render("secrets" , { userWithSecret: foundUser});
        }
      }
   });
});
app.get("/logout",(req,res , next)=>{
    req.logOut((err)=>{
        if(err) {
            return next(err);
        }
        res.redirect("/");
    });
   
});
app.post('/register',(req,res)=>{

      User.register({ username : req.body.username }, req.body.password ,(err, user)=>{
        if(err){
            console.log(err);
            res.redirect("/register");
        }else{
            passport.authenticate("local")(req,res ,()=>{
                res.redirect("/secrets");
            });
        }
      });
});


app.get("/login",(req,res)=>{
    res.render("login");
}); 
app.post("/login",(req,res)=>{
    
    const currentUser = new User({
        username : req.body.username,
        password : req.body.password 
    });

    req.login(currentUser , (err)=>{
        if(err) { 
            console.log(err);
            res.redirect("/login");
        }else{
            passport.authenticate("local")(req,res ,()=>{
                res.redirect("/secrets");
            });
        }
    });
});
app.get("/submit",(req,res)=>{
    if(req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect("/login");
    }

});

app.post("/submit",(req,res)=>{
    const submittedSecret = req.body.secret ;
    User.findById(req.user.id , (err, foundUser)=>{
            if(err) {
                console.log(err)
            }else{
                if(foundUser){
                    foundUser.secret = submittedSecret ; 
                    foundUser.save(()=>{
                        res.redirect("/secrets");
                    })
                }
            }
    });

});
app.listen(3000,(err)=>{
    console.log('server is running on port 3000');
});