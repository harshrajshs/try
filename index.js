const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const cookieParser = require("cookie-parser");
const cors = require('cors');

dotenv.config();

// Set up server
const app = express();
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server started on port : ${PORT}`));

app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: [
    "https://srijanhomeschool.netlify.app",
  ],
  credentials: true,
})); // Enable CORS for all routes

// Connect to mongoose

async function connectDB() {
  try {
    await mongoose.connect(process.env.MDB_CONNECT, {
    });
    console.log('MongoDB connected');
  } catch (err) {
    console.error('Failed to connect to MongoDB', err);
    process.exit(1); // Exit process with failure
  }
}

connectDB();

// Set up Routes

app.use("/", require("./routers/userRouter"));
