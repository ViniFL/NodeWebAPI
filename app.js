// Imports 
require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

// Configuração do express para JSON
app.use(express.json())

// Models
const User = require('./models/User')

// Rota publica - Rota aberta
app.get('/', (req, res) => {
    res.status(200).json({ msg: 'Bem vindo a API' })
})

// Rota privada
app.get('/user/:id', checkToken, async (req, res) => {

    const id = req.params.id

    // Checar se usuário existe
    const user = await User.findById(id, '-password')

    if(!user) {
        return res.status(404).json({ msg: 'Usuário não encontrado'})
    }

    res.status(200).json({ user })
})

function checkToken(req, res, next) {
    
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if(!token) {
        return res.status(401).json({ msg: 'Acesso negado' })
    }

    try {
        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next()
    } catch(error) {
        res.status(400).json({msg: "Token inválido"})
    }
}

// Registro de cadastro de usuário
app.post('/auth/register', async(req, res) => {

    const {name, email, password, confirmpassword} = req.body
    // Validação 
    if(!name) {
        return res.status(422).json({ msg: 'O nome é obrigatório!' })
    }

    if(!email) {
        return res.status(422).json({ msg: 'O e-mail é obrigatório!' })
    }

    if(!password) {
        return res.status(422).json({ msg: 'A senha é obrigatória!' })
    }
    
    if(password !== confirmpassword) {
        return res.status(422).json({ msg: 'As senhas não conferem' })
    }

    // Conferindo se usuário existe
    const userExist = await User.findOne({ email: email })

    if (userExist) {
        return res.status(422).json({ msg: 'Esse e-mail já foi utilizado' })
    }

    // Criando a senha
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    // Criando usuário
    const user = new User({
        name,
        email,
        password: passwordHash,
    })

    try {

        await user.save()

        res.status(201).json({ msg: 'Usuário criado com sucesso!' })

    } catch(error) {
        console.log(error)

        res.status(500).json({ msg: 'Erro no servidor, tente novamente mais tarde' })

    }
})

// Rota de Login
app.post("/auth/login", async (req, res) => {

    const {name, password} = req.body

    // Validação
    if(!name) {
        return res.status(422).json({ msg: 'O nome está incorreto!' })
    }

    if(!password) {
        return res.status(422).json({ msg: 'Senha inválida!' })
    }

    // Verificação de usuário existente
    const user = await User.findOne({ name: name })

    if (!user) {
        return res.status(404).json({ msg: 'Usuário não encontrado' })
    }

    // Verificação de senha correta
    const checkPassword = await bcrypt.compare(password, user.password)

    if(!checkPassword) {
        return res.status(422).json({ msg: 'Senha inválida!' })
    }

    try {

        const secret = process.env.SECRET

        const token = jwt.sign(
            {
            id: user._id
            },
            secret,
        )

        res.status(200).json({msg: "Autenticação realizada com sucesso", token})

    } catch { 
        console.log(error)

        res.status(500).json({ msg: 'Erro no servidor, tente novamente mais tarde' })
    }
})

// Credenciais e acesso ao banco
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose.set('strictQuery', true);
mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.ouusdkm.mongodb.net/?retryWrites=true&w=majority`).then(() => {
    app.listen(5028)
}).catch((err) => console.log(err))

