import {app} from './app.js'
import dotenv from "dotenv"
import connectDB from './db/index.js'

dotenv.config({
    path: "./.env"

})


const port = process.env.PORT || 8003

connectDB()
.then(() => {
    app.listen(port,() => {
        console.log(`I am listening in the port ${port}`);
    })
})
.catch((err) => {
    console.log('MongoDb connection user');
    
})