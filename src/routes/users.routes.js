import {Router} from "express"
import { registerUser, logoutUser, loginUser, refreshAccessToken, changeCurrentPassword, getCurrentUser, getUserChannelProfile, updateAccountDetails, updateUserAvatar, updateUserCoverImage, getWatchHistory } from "../controllers/user.controller.js"
import { upload } from "../middlewares/multer.middleware.js"
import {verifyJWT} from "../middlewares/auth.middleware.js"

const router = Router()

//unsecure route
router.route("/register").post(
    upload.fields([
        {name : "avatar", maxCount:1},
        {name : "coverImage", maxCount:1}
    ]) 
    ,registerUser)

router.route("/login").post(loginUser)
router.route("/refresh-token").post(refreshAccessToken)


//secure route
router.route("/logout").post(verifyJWT, logoutUser)
router.route("/change-password").post(verifyJWT, changeCurrentPassword)
router.route("/current-user").get(verifyJWT, getCurrentUser)
router.route("/c/:username").get(verifyJWT, getUserChannelProfile)
router.route("/update-account").patch(verifyJWT, updateAccountDetails)
router.route("/avatar").patch(verifyJWT, upload.single("avatar"),updateUserAvatar)
router.route("/coverImage").patch(verifyJWT, upload.single("coverImage"),updateUserCoverImage)
router.route("/watch-history").get(verifyJWT, getWatchHistory)


export default router
