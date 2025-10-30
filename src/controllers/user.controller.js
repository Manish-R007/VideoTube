import { asyncHandler } from "../utils/asyncHandler.js"
import { ApiError } from "../utils/ApiError.js"
import { User } from "../models/user.models.js"
import { uploadToCloudinary, deleteFromCloudinary } from "../utils/cloudinary.js"
import { Apiresponse } from "../utils/Apiresponse.js"
import jwt from "jsonwebtoken"

const generatAccessTokenandRefreshToken = async (userId) => {
    try {
        const user = await User.findById(userId)

        if (!user) {
            throw new ApiError("404", "User not found")
        }

        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({ ValidtaeBeforeSave: false })

        return { accessToken, refreshToken }
    } catch (error) {
        throw new ApiError(500, "Failed to generate tokens")
    }
}

const registerUser = asyncHandler(async (req, res) => {
    const { fullname, email, username, password } = req.body


    if (!fullname || !email || !username || !password) {
        throw new ApiError(400, "All fields are required")
    }

    const existedUser = await User.findOne({
        $or: [{ email }, { username: username.toLowerCase() }]
    })
    if (existedUser) {
        throw new ApiError(409, "User with email or username already exists")
    }


    const avatarFile = req.files?.avatar?.[0]
    const coverImageFile = req.files?.coverImage?.[0]

    let avatar, coverImage


    if (avatarFile) {
        try {
            avatar = await uploadToCloudinary(avatarFile.path)
            console.log("Uploaded avatar:", avatar.url)
        } catch (error) {
            console.error("Error uploading avatar:", error)
            throw new ApiError(500, "Failed to upload avatar")
        }
    }


    if (coverImageFile) {
        try {
            coverImage = await uploadToCloudinary(coverImageFile.path)
            console.log("Uploaded cover image:", coverImage.url)
        } catch (error) {
            console.error("Error uploading cover image:", error)
            if (avatar) await deleteFromCloudinary(avatar.public_id) // cleanup
            throw new ApiError(500, "Failed to upload cover image")
        }
    }


    try {
        const user = await User.create({
            fullname,
            email,
            username: username.toLowerCase(),
            password,
            avatar: avatar?.url || "https://yourcdn.com/default-avatar.png",
            coverImage: coverImage?.url || ""
        })


        const createdUser = await User.findById(user._id).select("-password -refreshToken")

        if (!createdUser) {
            if (avatar) await deleteFromCloudinary(avatar.public_id)
            if (coverImage) await deleteFromCloudinary(coverImage.public_id)
            throw new ApiError(500, "Failed to fetch created user")
        }


        return res.status(201).json(
            new Apiresponse(
                201,
                { createdUser },
                "User registered successfully"
            )
        )
    } catch (error) {
        console.error("User creation failed:", error)


        if (error.code === 11000) {
            throw new ApiError(409, "Email or username already exists")
        }

        s
        if (avatar) await deleteFromCloudinary(avatar.public_id)
        if (coverImage) await deleteFromCloudinary(coverImage.public_id)

        throw new ApiError(500, "Something went wrong while creating the user")
    }
})

const loginUser = asyncHandler(async (req, res) => {
    const { username, email, password } = req.body

    if (!password || (!username && !email)) {
        throw new ApiError(400, "All fileds are required")
    }

    const existedUser = await User.findOne({
        $or: [{ email }, { username }]
    })

    if (!existedUser) {
        throw new ApiError(404, "User not found")
    }

    const isPasswordValid = await existedUser.isPasswordCorrect(password)

    if (!isPasswordValid) {
        throw new ApiError(401, "Invalid password")
    }

    const { accessToken, refreshToken } = await generatAccessTokenandRefreshToken(existedUser._id)

    const loggedInUser = await User.findById(existedUser._id).select("-password -refreshToken")

    const options = {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production"
    }

    return res.status(200)
        .cookie('accessToken', accessToken, options)
        .cookie('refreshToken', refreshToken, options)
        .json(
            new Apiresponse(
                200,
                { user: loggedInUser },
                "User logged in successfully"
            )
        )


})

const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken = req.cookies?.refreshToken || req.body?.refreshToken

    if (!incomingRefreshToken) {
        throw new ApiError(400, "Refresh token is required")
    }

    try {
        const decodedToken = jwt.verify(incomingRefreshToken, REFRESH_TOKEN_SECRET)
        const user = await User.findById(decodedToken?._id)

        if (!user) {
            throw new ApiError(404, "Invalid refresh Token")
        }

        if (user?.refreshToken !== incomingRefreshToken) {
            throw new ApiError(401, "Refresh token expired,please login again")
        }

        const { accessToken, newRefreshToken } = await generatAccessTokenandRefreshToken(user._id)

        const options = {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production"
        }

        return res.status(200)
            .cookie('accessToken', accessToken, options)
            .cookie('refreshToken', newRefreshToken, options)
            .json(
                new Apiresponse(
                    200,
                    { accessToken, refreshToken: newRefreshToken },
                    "Access token refreshed successfully"
                )
            )

    } catch (error) {
        throw new ApiError(401, "Invalid refresh token")
    }
})

const logoutUser = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(req.user?._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
    }

    return res
        .status(200)
        .clearCookie('accessToken', options)
        .clearCookie('refreshToken', options)
        .json(
            new Apiresponse(
                200,
                {},
                "User logged out successfully"
            )
        )
})

const changeCurrentPassword = asyncHandler(async (req, res) => {
    const { oldPassword, newPassword } = req.body
    const user = await User.findById(req.user?._id)

    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

    if (!isPasswordCorrect) {
        throw new ApiError(404, "old password is incorrect")
    }

    user.password = newPassword

    await user.save({ ValidtaeBeforeSave: true })

    return res.status(200).json(
        new Apiresponse(
            200,
            {},
            "Password changed successfully"
        )
    )
})

const getCurrentUser = asyncHandler(async (req, res) => {
    return res.status(200).json(
        new Apiresponse(
            200,
            { user: req.user },
            "Current user fetched successfully"
        )
    )
})

const updateAccountDetails = asyncHandler(async (req, res) => {
    const { fullname, email } = req.body

    if (!fullname || !email) {
        throw new ApiError(400, "Fullname and email are required")
    }

    const user = await User.findByIdAndUpdate(req.user?._id,
        {
            $set: {
                fullname,
                email: email
            }
        },
        {
            new: true
        }
    ).select("-password -refreshToken")

    return res.staus(200).json(
        new Apiresponse(
            200,
            { user },
            "Account details updated successfully"
        )
    )
})

const updateUserAvatar = asyncHandler(async (req, res) => {
    const avatarLocalPath = req.file?.path
    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar image is required")
    }

    const avatar = await uploadToCloudinary(avatarLocalPath)

    if (!avatar.url) {
        throw new ApiError(500, "Failed to upload avatar")
    }

    await User.findByIdAndUpdate(req.user?._id,
        {
            $set: {
                avatar: avatar.url
            }
        },
        {
            new: true
        }
    ).select("-password -refreshToken")

    return res.status(200).json(
        new Apiresponse(
            200,
            { avatar: avatar.url },
            "User avatar updated successfully"
        )
    )
})

const updateUserCoverImage = asyncHandler(async (req, res) => {
    const coverImageLocalPath = req.file?.path

    if (!coverImageLocalPath) {
        throw new ApiError(400, "Cover image is required")
    }

    const coverImage = await uploadToCloudinary(coverImageLocalPath)

    if (!coverImage.url) {
        throw new ApiError(500, "Failed to upload cover image")
    }

    await User.findByIdAndUpdate(req.user?._id, {
        $set: {
            coverImage: coverImage.url
        }
    },
        {
            new: true
        }
    ).select("-password -refreshToken")

    return res.status(200).json(
        new Apiresponse(
            200,
            { coverImage: coverImage.url },
            "User cover image updated successfully"
        )
    )
})

const getUserChannelProfile = asyncHandler(async (req, res) => {
    const { username } = req.params
    if (!username) {
        throw new ApiError("User doesn't Exixts")
    }

    const channel = await User.aggregate(
        [
            {
                $match: {
                    username: username?.toLowerCase()
                }
            },
            {
                $lookup: {
                    from: "subscriptons",
                    localField: "_id",
                    foreignField: 'channel',
                    as: "subscribers"
                }
            },
            {
                $lookup: {
                    from: "subscriptons",
                    localField: '_id',
                    foreignField: 'subscriber',
                    as: "subscribedto"

                }
            },
            {
                $addFields: {
                    subscribersCount: {
                        $size: "$subscribers"
                    },

                    channelSubsceribedToCount: {
                        $size: "$subscribedto"
                    },

                    isSubsceribed : {
                        $cond : {
                            if : {
                                $in: [req.user?._id, "$subsceribers.subscriber"]
                            },
                            then : true,
                            else : false
                        }
                    }

                }
            },
            {
                $project: {
                    fullname: 1,
                    username: 1,
                    email: 1,
                    avatar: 1,
                    subscribersCount : 1,
                    channelSubsceribedToCount : 1,
                    isSubsceribed : 1,
                    coverImage: 1
                }
            }
        ]
    )

    if(channel.length === 0){
        throw new ApiError(404,"User not found")
    }

    return res.staus(200).json(
        new Apiresponse(
            200,
            { channel: channel[0] },
            "User channel profile fetched successfully")
    )

})

const getWatchHistory = asyncHandler(async (req, res) => {
    const user = await User.aggregate(
        [
            {
                $match: {
                    _id: new mongoose.Types.ObjectId(req.user?._id)
                }
            },
            {
                $lookup: {
                    from: "videos",
                    localField: "watchHistory",
                    foreignField: "_id",
                    as: "watchHistoryVideos",
                    pipeline: [
                        {
                            $lookup: {
                                from: "users",
                                localField : "owner",
                                foreignField : "_id",
                                as : "owner",
                                pipeline: [
                                    {
                                        $project : {
                                            fullname : 1,
                                            username : 1,
                                            avatar : 1
                                        }
                                    }
                                ]
                            }
                        },
                        {
                            $addFields: {
                                owner : {
                                    $first: "$owner"
                                }
                            }
                        }
                    ]
                }
            }
        ]
    )

    if(!user || user.length === 0){
        throw new ApiError(404,"User not found")
    }

    return res.status(200).json(
        new Apiresponse(
            200,
            { watchHistory: user[0].watchHistory},
            "User watch history fetched successfully"
        )
    )
})

export {
    registerUser,
    loginUser,
    refreshAccessToken,
    logoutUser,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage,
    getUserChannelProfile,
    getWatchHistory
}
