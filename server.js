const express = require('express')
var bodyParser = require('body-parser')
const app = express()
const mongoose = require('mongoose');
app.use(bodyParser.json())
const path = require('path')
const {model : User}= require('./model/user')
var bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const JWT_SECRET ='qjdkjashdwdjqhjhdjAHDJdf'
mongoose.connect("mongodb://localhost:27017/login-app-db",{useNewUrlParser:true,useUnifiedTopology:true})

app.use('/', express.static(path.join(__dirname,'static')))

//change password
app.post('/api/change-password', async (req, res) => {
	const { token, newpassword: plainTextPassword } = req.body

	if (!plainTextPassword || typeof plainTextPassword !== 'string') {
		return res.json({ status: 'error', error: 'Invalid password' })
	}

	if (plainTextPassword.length < 5) {
		return res.json({
			status: 'error',
			error: 'Password too small. Should be atleast 6 characters'
		})
	}

	try {
		const user = jwt.verify(token, JWT_SECRET)

		const _id = user.id

		const password = await bcrypt.hash(plainTextPassword, 10)

		await User.updateOne(
			{ _id },
			{
				$set: { password }
			}
		)
		res.json({ status: 'ok' })
	} catch (error) {
		console.log(error)
		res.json({ status: 'error', error: ';))' })
	}
})


//login
app.post('/api/login', async (req, res) => {
	const { username, password } = req.body
	const user = await User.findOne({ username }).lean()

	if (!user) {
		return res.json({ status: 'error', error: 'Invalid username/password' })
	}

	if (await bcrypt.compare(password, user.password)) {
		// the username, password combination is successful

		const token = jwt.sign(
			{
				id: user._id,
				username: user.username
			},
			JWT_SECRET
		)

		return res.json({ status: 'ok', data: token })
	}

	res.json({ status: 'error', error: 'Invalid username/password' })
})

//register
app.post('/api/register', async (req, res) => {
    const { username, password: plainTextPassword } = req.body;
    const password = await bcrypt.hash(plainTextPassword,10)
        if(!username || typeof username !== 'string'){
            return res.json({status:'error', error:"invalid USername"})
        }
        if(!plainTextPassword || typeof plainTextPassword !== 'string'){
            return res.json({status:'error', error:"invalid password"})
        }
        if(plainTextPassword.length < 5){
            return res.json({status:'error', error: 'Password is too small'})
        }


    try{
            const response = new User({
                username:username,
                password:password
            })
            await response.save()
            console.log(response)
    }catch(e){
        console.log(JSON.stringify(e));
        return res.json({status:'error'})
    }
    res.json({status:'ok'})
})

    
 
app.listen(3001,() =>{
    console.log("server at 3001");
})