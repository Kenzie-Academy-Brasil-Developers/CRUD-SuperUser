import express, { response } from 'express'
import users from './database'
import { v4 as uuidv4 } from 'uuid'
import { hash, compare } from 'bcryptjs'
import jwt from 'jsonwebtoken'
import 'dotenv/config'


const app = express()
app.use(express.json())

// MIDDLEWARES
const ensureAuthMiddleware = (request, response, next) => {

    let authorization = request.headers.authorization

    if(!authorization){
        return response.status(401).json({
            "message": "Missing authorization headers"
        })
    }

    authorization = authorization.split(' ')[1]

    return jwt.verify(authorization, process.env.SECRET_KEY, (error, decoded) => {
        if(error){
            return response.status(401).json({
                "message": "Missing authorization headers"
            })
        }

        request.user = {
            id: decoded.sub,
        }

        return next()

    })
}

const ensureIsAdm = (request, response, next) => {
    const user = users.find(el => el.uuid === request.user.id)

    if(user.isAdm === false){
        return response.status(403).json({
            "message": "missing admin permissions"
        })
    }

    return next()
}

// SERVICES
const createUserService = async (userData) => {
    const userArealdyExists = users.find((user) => user.email === userData.email);
  
    if (userArealdyExists) {
      return [409, {
        "message": "E-mail already registered"
      }];
    }
  
    const user = {
        uuid: uuidv4(),
        ...userData,
        password: await hash(userData.password, 10),
        createdOn: new Date(),
        updatedOn: new Date()
    }
    users.push(user)
    return [201, {
        name: user.name,
        email: user.email,
        uuid: user.uuid,
        createdOn: user.createdOn,
        updatedOn: user.updatedOn,
        isAdm: user.isAdm
    }]
};

const createSessionService = async ({email, password}) => {

    const user = users.find(el => el.email === email)

    if(!user){
        return [401, {
            "message": "Wrong email/password"
        }]
    }

    const passwordMatch = await compare(password, user.password)

    if(!passwordMatch){
        return [401, {
            "message": "Wrong email/password"
        }]
    }

    const token = jwt.sign(
        {

        },
        process.env.SECRET_KEY,
        {
            expiresIn: "24h",
            subject: user.uuid
        }
    )

    return [200, {token}]
}

const listUsersService = () => {
    return [200, users]
}

const listUserLogedService = (id) => {
    const user = users.find(el => el.uuid === id)
    return [200, {
        name: user.name,
        email: user.email,
        uuid: user.uuid,
        createdOn: user.createdOn,
        updatedOn: user.updatedOn,
        isAdm: user.isAdm
    }]
}

const deleteUserService = (id) => {
    console.log(id)
    const userIndex = users.findIndex(el => el.uuid === id)
    users.splice(userIndex, 1)
    console.log(users)
    return [204, {}]
}

const editUserService = async  (id, data) => {

    const user = users.find(el => el.uuid === id)

    let newName = user.name
    let newEmail = user.email
    let newPassword = user.password

    if(data.name) {
        newName = data.name
    }
    if(data.email) {
        newEmail = data.email
    }
    if(data.password){
        newPassword = await hash(data.password, 10)
    }
    
    let newUser = {
        email: newName,
        name: newName,
        password: newPassword,
        createdOn: user.createdOn,
        updatedOn: new Date(),
        isAdm: user.isAdm
    }

    return [201, {
        name: newUser.name,
        email: newUser.email,
        uuid: newUser.uuid,
        createdOn: newUser.createdOn,
        updatedOn: newUser.updatedOn,
        isAdm: newUser.isAdm
    }]
}


// CONTROLLERS
const createUserController = async (request, response) => {
    const [status, data] = await createUserService(request.body)
    return response.status(status).json(data)
}

const createSessionController = async (request, response) => {
    const [status, data] = await createSessionService(request.body)
    return response.status(status).json(data)
}

const listUsersController = (request, response) => {
    const [status, data] = listUsersService()
    return response.status(status).json(data)
}

const listUserLogedController = (request, response) => {
    const [status, data] = listUserLogedService(request.user.id)
    return response.status(status).json(data)
}

const deleteUserController = (request, response) => {
    const [status, data] = deleteUserService(request.user.id)
    return response.status(status).json(data)
}

const editUserController = async (request, response) => {
    const [status, data] = await editUserService(request.user.id, request.body)
    return response.status(status).json(data)
}


// ROTAS 
app.post("/users", createUserController);
app.get('/users', ensureAuthMiddleware, ensureIsAdm, listUsersController);
app.post('/login', createSessionController);
app.get('/users/profile',ensureAuthMiddleware, listUserLogedController);
app.delete('/users/:id',ensureAuthMiddleware, ensureIsAdm, deleteUserController);
app.patch('/users/:id',ensureAuthMiddleware, ensureIsAdm, editUserController);

app.listen(3000, () => {
    console.log('Server running in port 3000')
})
export default app