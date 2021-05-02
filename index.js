const express = require("express");
const app = express();
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser');
const cors = require('cors');


app.use(cors({credentials: true, origin:'http://localhost:3000'}));
app.use(express.json());
app.use(cookieParser());

async function auth(req, res, next){
    // let token= req.headers['authorization'];
    // token = token.split(' ')[1];
    if(req.cookies.access) {
        jwt.verify(req.cookies.access,'access', (err, user)=>{
            if(!err){
                req.user = user;
                next();
            }
        })
    } else {
        if(req.cookies.refreshToken){
            let tok = req.cookies.refreshToken;
            jwt.verify(tok, 'refresh', async (err, user)=> {
                if(!err) {
                    const accessToken = await jwt.sign({username: 'ankur'}, "access", {expiresIn:'5s'});
                    const refreshToken = await jwt.sign({username: 'ankur'}, "refresh", {expiresIn:'2m'});

                    res.cookie('access', accessToken,{
                        sameSite:'strict',
                        path:'/',
                        expires: new Date(new Date().getTime() + 5*1000)
                    });
                    res.cookie('refreshToken', refreshToken,{
                        sameSite:'strict',
                        path:'/',
                        expires: new Date(new Date().getTime() + 120*1000),
                        httpOnly:true
                    });
                    next();
                } else{
                    return res.status(403).json({message: "User not authenticated"});
                }
            });
        } else {
            return res.status(403).json({message: "User not authenticated"});
        }
    }

}

app.get('/protected', auth, (req, res) =>{
    res.json({message: "inside the protected route"});
});

app.post('/renew', (req,res)=>{
    const refreshToken = req.body.token;
    if(!refreshToken) {
        return res.status(403).json({message:"User not authenticated"});
    }
    jwt.verify(refreshToken, 'refresh', (err, user)=>{
        if(!err){
            const accessToken = jwt.sign({username: user.name}, "access", {expiresIn:'5s'});
            return res.status(201).json({accessToken});
        } else{
            return res.status(403).json({message:"User not authenticated"});
        }
    });
});


app.get ('/login', (req, res)=>{
    // const {user} = req.body;
    // if(!user){
    //     return res.status(404).json({message:"Empty Body"});
    // }
    let accessToken = jwt.sign({name:"ankur"},'access', {expiresIn:'5s'});
    let refreshToken= jwt.sign({name:"ankur"}, 'refresh', {expiresIn: '2m'});


    return res.status(201)
    .cookie('refreshToken', refreshToken,{
        sameSite:'strict',
        path:'/',
        expires: new Date(new Date().getTime() + 120*1000),
        httpOnly:true
    })
    .cookie('access', accessToken,{
        sameSite:'strict',
        path:'/',
        expires: new Date(new Date().getTime() + 5*1000)
    }).json({
        accessToken,
        refreshToken
    })
});

async function renewCookie(refreshToken){
    await jwt.verify(refreshToken, 'refresh', (err, user)=>{
        if(!err){
            const accessToken = jwt.sign({username: 'ankur'}, "access", {expiresIn:'5s'});
            return accessToken;
        } else{
            return null;
        }
    });
}
app.listen(1525)
