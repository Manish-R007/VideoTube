import {Router} from "express"
import {healthcheck} from "../controllers/Healthcheck.controller.js"

const router = Router()

router.route("/").get(healthcheck)

export default router