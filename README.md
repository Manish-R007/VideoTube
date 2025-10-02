This backend powers a video-sharing platform, similar to YouTube, allowing users to register, upload videos, interact with content, and manage their profiles.

🛠️ Tech Stack Details

Layer	Technology	Description

Backend	Node.js	JavaScript runtime for building scalable server-side applications

Framework	Express.js	Web framework for routing, middleware, and RESTful API structure

Database	MongoDB + Mongoose	NoSQL database for storing users, videos, comments, etc.; Mongoose for ODM

File Uploads	Multer	Middleware for handling multipart/form-data (file uploads)

Cloud Storage	Cloudinary	Stores and serves images/videos efficiently

Auth	JWT	JSON Web Tokens for secure user authentication and session management

📦 Folder Structure & Roles

controllers/: Functions that process requests, interact with models, and send responses (e.g., user registration, video upload).

models/: Mongoose schemas for each entity (User, Video, Comment, etc.), defining data structure and relationships.

routes/: Maps HTTP endpoints to controller functions (e.g., users, /videos).

middlewares/: Reusable logic for authentication (JWT), file uploads (Multer), etc.

utils/: Helper classes for error handling, API responses, async operations, and cloudinary integration.

db/: Database connection setup.

temp: Temporary storage for uploaded files, such as avatars before processing.

🚀 Key Features

User Management: Register, login, update profile, upload avatar.

Video Management: Upload, view, like, comment, and organize videos into playlists.

Social Features: Subscribe to users, like/dislike videos, comment on videos.

Health Check: Endpoint to verify server status.

Error Handling: Custom error and response classes for consistent API output.

Cloudinary Integration: Efficient media storage and retrieval.

🧩 How It Works

Users interact with the frontend, sending requests to the backend API.

Requests are routed via Express to the appropriate controller.

Controllers use models to read/write data in MongoDB.

Middleware handles authentication, file uploads, and error responses.

Uploaded media is stored in Cloudinary, with temporary files managed in temp.
