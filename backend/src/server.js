import express from "express";
import notesRoutes from "./routes/notesRoutes.js";
import { connectDB } from "./config/db.js";

import cors from "cors";

// package needed to use hidden secret variables, enviornment variables
import dotenv from "dotenv";
// calling config method to properly use it
dotenv.config();

const app = express();
// IF port UNDEFINED DEFAULT TO 5001
const PORT = process.env.PORT || 5001

connectDB();


//middleware
app.use(express.json()); // this middleware will parse JSON bodies: req.body
app.use(cors());

// middleware is a perfect use case for authentication

// our simple custom middleware
app.use((req,res,next) => {
    console.log(`Req method is ${req.method} & Req URL is ${req.url}`);
    next();
});

app.use("/api/notes", notesRoutes);



app.listen(5001, () => {
    console.log("Server started on port" , PORT);
});

// mongodb+srv://dylansm37_db_user:EOWSSAAku6IucH2i@cluster0.lcn0bgi.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0