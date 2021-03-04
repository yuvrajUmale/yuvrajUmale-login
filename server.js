require('dotenv').config();

const { name } = require('ejs');
const express = require('express');
const { pool } = require('./dbConfig');
const ejs = require('ejs');
const bcrypt = require('bcrypt');
const app = express();
const session = require('express-session');
const flash = require('express-flash');
const passport = require('passport');

const initializePassport = require('./passportConfig');

initializePassport(passport);

const port = process.env.PORT || 3000;

app.set("view engine", "ejs"); //import ejs folder

//middlewares
app.use(express.urlencoded({extended:false}));
app.use(express.json());
app.use(session({
    secret:process.env.SECRET,
    resave:false,
    saveUninitialized:false
    }
));

app.use(passport.initialize()); //function that initialize the passport

app.use(passport.session()); //function that stores our variables in the session

app.use(flash());
// routes

// const pool = new Pool({
//     user: process.env.DB_USER,
//     password: process.env.DB_PASSWORD,
//     host: process.env.DB_HOST,
//     port: process.env.DB_PORT,
//     database: process.env.DB_DATABASE
// });


//home route
app.get('/', (req, res) => {
    res.render('home')
});

//register route 
app.get('/users/register', (req, res) => {
    res.render('register')
});

//login route
app.get('/users/login', (req, res) =>{
    res.render('login');
})

//logout route
app.get('/users/logout', (req, res) =>{
    req.logout();
    res.render('home', {message:"you have logged out successfully"});
})

//secret route
app.get('/users/secret', (req, res) =>{
    res.render('secret', {user : req.user.name})
});

app.post('/users/register', async(req, res)=>{
    // console.log({
        //     name,
        //     email,
        //     password,
        //     password2
        // });
        try{
        let {name, email, password,password2} = req.body;
        
        let error = [];

        if(!name || !email || !password || !password2){
            error.push({message:"Please enter all required fields"})
        }       
         if(password.length<6){
            error.push({message:"Password should be at least 6 characters"})
        } 
         if( password != password2){
          error.push({message:"Password do not match"})
        }
         if(error.length > 0){
            res.render("register", {error})
        }
        else{
            
            //form validation is successful
            let hashpassword = await bcrypt.hash(password, 10);
            //console.log(hashpassword);
            
            const allUsers = await pool.query("select * from users where email = $1", [email]);

            console.table(allUsers.rows)
            //res.json(results.rows);
            if(allUsers.rows.length> 0){
               error.push({message:"email already exitst"})
                res.render("register",{error})
            }
            else{
                const newUsers = await pool.query("insert into users (name, email, password) values($1,$2,$3) returning id, password", [name,email,hashpassword]);

                console.table(newUsers.rows)
                req.flash("success_msg", "You are now registered. Please log in");
                res.redirect("/users/login");

            }
        }
    }
    catch (err) {
        console.log(`something is wrong ${err}`);
    }  
});

app.post("/users/login", passport.authenticate("local", {
    successRedirect: "/users/secret",
    failureRedirect: "/users/login",
    failureFlash: true
}));


function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()){
        return res.redirect("/");
    }
    next();
}


function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return next();
    }
    res.redirect("/users/login");
  }

app.listen(port, () => {
    console.log(`server is runnig on ${port}`);
})