import { v2 as cloudinary } from 'cloudinary';
import fs from "fs"
import dotenv from "dotenv"
dotenv.config()

 cloudinary.config({ 
        cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
        api_key: process.env.CLOUDINARY_API_KEY, 
        api_secret: process.env.CLOUDINARY_API_SECRET // Click 'View API Keys' above to copy your API secret
});

const uploadToCloudinary = async (localfilepath) => {
    try {
        if(!localfilepath) return null
        const response = await cloudinary.uploader.upload(localfilepath,{
            resource_type: "auto",
        })
        console.log("File uploaded to Cloudinary:", response.url);
        fs.unlinkSync(localfilepath)
        return response
    } catch (error) {
        fs.unlinkSync(localfilepath)
        return null
    }
}

const deleteFromCloudinary = async (publicId) => {
    try {
        const result = cloudinary.uploader.destroy(publicId)
        console.log("Deleted from cloudinary",publicId);
        
    } catch (error) {
        console.log("Error deleting from cloudinary",error);
        return null
        
    }
}

export {uploadToCloudinary,deleteFromCloudinary}