/// importação dos modulos que vão ser utilizados
require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

//configuração do JSON para ele ser reconhecido
app.use(express.json())


//Pasta models sendo puxada para meu app
const User = require('./models/User')

//rota de usuarios pagina inicial
app.get('/', (req, res) => {
    res.status(200).json({msg: 'Teste da gambiarra'})
})

//rota privada para pessoas que tem a conta ja cadastrada pelo token
app.get("/user/:id", verifitoken, async (req, res) => {
    const id = req.params.id


    //verificação para saber se o usuario existe
    const user = await User.findById(id, '-password')

    if(!user) {
        return res.status(404).json({erro: 'Usuário não encontrado'})
    }
    res.status(200).json({user})
})

//verificação do token para transformar a rota em privada
function verifitoken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if(!token) {
        return res.status(401).json({erro: 'Acesso não permitido'})
    }
    try {

        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next()

    }catch (error) {
        res.status(400).json({erro: ' O Token que está sendo fornecido se encontra invalido'})
    }
} 
// Registro de usuarios
app.post('/auth/register', async (req, res) => {

    const {name, email, password, confirmpassword} = req.body

    if(!name) {
        return res.status(422).json({erro: 'Por favor digite seu nome!'})
    }

    if(!email) {
        return res.status(422).json({erro: 'Por favor digite seu email!'})
    }

    if(!password) {
        return res.status(422).json({erro: 'Digite sua senha!'})
    }
    if(password !== confirmpassword) {
        return res.status(422).json({erro: 'Sua senha está diferente da digitada!'})
    }

    const userExists = await User.findOne({email: email})

    if(userExists) {
        return res.status(422).json({erro: 'Esse email ja está em uso'})
    }

    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    const user = new User({
        name,
        email,
        password: passwordHash,   
    })

    try {
        
        await user.save()

        res.status(201).json({mensagem: 'O usuário foi criado e está pronto para ser utilizado'})
    } catch (error) {
        console.log(error)

        res
            .status(500)
            .json({mensagem: 'Estamos com problemas no servidor tente novamente mais tarde',
        })    

    }
})

app.post("/auth/login", async (req, res) => {
    
    const {email, password} = req.body

    if(!email) {
        return res.status(422).json({erro: 'Por favor digite seu email!'})
    }

    if(!password) {
        return res.status(422).json({erro: 'Digite sua senha!'})
    }

    const user = await User.findOne({email: email})

    if(!user) {
        return res.status(404).json({erro: 'Login não encontrado'})
    }

    const veripassword = await bcrypt.compare(password, user.password)

    if(!veripassword) {
        return res.status(422).json({erro: 'Senha incorreta!'})
    }

    try{
        const secret = process.env.SECRET

        const token = jwt.sign(
            {
                id: user._id,
            }, 
            secret,
            )
        
            res
                .status(200)
                .json({mensagem: 'Parabéns por efetuar sua autenticação', token
            })

    }catch (error) {
        console.log(error)
    
            res
                .status(500)
                .json({mensagem: 'Estamos com problemas no servidor tente novamente mais tarde',
            })    
     }
})

/// Criando as credencias do banco de dados
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose
    .connect(
        `mongodb+srv://${dbUser}:${dbPassword}@cluster0.mxjqkej.mongodb.net/?retryWrites=true&w=majority&appName=AtlasApp`,
        )
    .then(() => {
        app.listen(3000)
        console.log('Servidor rodando na porta 3000')
})
.catch((err) => console.log(err))

