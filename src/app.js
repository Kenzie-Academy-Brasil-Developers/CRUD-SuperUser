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

const deleteUserService = (idToken, id) => {

    const userLoged = users.find(el => el.uuid === idToken)

    if(userLoged.isAdm === true){
        const userIndex = users.findIndex(el => el.uuid === id)
        users.splice(userIndex, 1)
        return [204, {}]
    } else if (id === idToken) {
        const userIndex = users.findIndex(el => el.uuid === idToken)
        users.splice(userIndex, 1)
        return [204, {}]
    } else {
        return [401, {
            "message": "Missing authorization headers"
        }]
    }

}

const editUserService = async  (idToken, data, id) => {
    console.log(idToken, data, id)
    const userLoged = users.find(el => el.uuid === idToken)

    if(userLoged.isAdm === true){

        const userIndex = users.findIndex(el => el.uuid === id)
        users[userIndex] = {...users[userIndex], ...data, updatedOn: new Date()}
      
        return [201, {
            name: users[userIndex].name,
            email: users[userIndex].email,
            uuid: users[userIndex].uuid,
            createdOn: users[userIndex].createdOn,
            updatedOn: users[userIndex].updatedOn,
            isAdm: users[userIndex].isAdm
        }]
    } else if (id === idToken) {
        const userIndex = users.findIndex(el => el.uuid === idToken)
        users[userIndex] = {...users[userIndex], ...data, updatedOn: new Date()}
      
        return [201, {
            name: users[userIndex].name,
            email: users[userIndex].email,
            uuid: users[userIndex].uuid,
            createdOn: users[userIndex].createdOn,
            updatedOn: users[userIndex].updatedOn,
            isAdm: users[userIndex].isAdm
        }]
    } else {
        return [403, {
            "message": "missing admin permissions"
          }]
    }

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
    const {id} = request.params
    const [status, data] = deleteUserService(request.user.id, id)
    return response.status(status).json(data)
}

const editUserController = async (request, response) => {
    const {id} = request.params
    const [status, data] = await editUserService(request.user.id, request.body, id)
    return response.status(status).json(data)
}


// ROTAS 
app.post("/users", createUserController);
app.get('/users', ensureAuthMiddleware, ensureIsAdm, listUsersController);
app.post('/login', createSessionController);
app.get('/users/profile',ensureAuthMiddleware, listUserLogedController);
app.delete('/users/:id', ensureAuthMiddleware, ensureIsAdm, deleteUserController);
app.patch('/users/:id',ensureAuthMiddleware, editUserController);

app.listen(3000, () => {
    console.log('Server running in port 3000')
})
export default app