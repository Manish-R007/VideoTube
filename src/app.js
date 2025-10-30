import express from 'express'
import cors from "cors"
import cookieParser from 'cookie-parser'

const app = express()

app.use(
    cors({
        origin: process.env.CORS_ORIGIN,
        credentials: true
    })
)

app.use(express.json({
    limit: "16kb"
}))

app.use(
    express.urlencoded({
        extended: true,
        limit: "16kb"
    })
)

app.use(express.static("public"))
app.use(cookieParser())

//importing routes
import  healthcheckrouter from './routes/healthcheck.routes.js'
import userRouter from './routes/users.routes.js'

app.use("/api/v1/healthcheck",healthcheckrouter)
app.use("/api/v1/users", userRouter)

// Global Error Handler
app.use((err, req, res, next) => {
    console.error(err) // logs full error in backend

    const statusCode = err.statusCode || 500
    const message = err.message || "Internal Server Error"

    res.status(statusCode).json({
        success: false,
        statusCode,
        message,
        ...(err.data && { data: err.data }) // optional extra data
    })
})


export {app}