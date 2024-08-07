import express from "express";
import dotenv from "dotenv";
import { dbConnection } from "./db/db.js";
import cookieParser from "cookie-parser";
import userRoutes from "./routes/user.routes.js";
import notesRoutes from "./routes/notes.routes.js";
import todosRoutes from "./routes/todos.routes.js";
import cors from "cors";
import helmet from "helmet";
import compression from "compression";
dotenv.config();
const app = express();

// built in middlewares
const allowedOrigins = [
  "https://keepnotesandtodos.netlify.app",
  "http://localhost:5173",
];
app.use(compression()); // Gzip compression
app.use(helmet()); // Secure HTTP headers
app.use(
  cors({
    origin: allowedOrigins,
    methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
    credentials: true,
  })
);
app.use(cookieParser());
app.use(express.json());
// app.use(urlencoded({ extended: true }));
app.get("/", (req, res) => {
  res.send("Notes api is working");
});

// routes
app.use("/api/users", userRoutes);
app.use("/api/notes", notesRoutes);
app.use("/api/todos", todosRoutes);

app.listen(process.env.PORT || 4000, () => {
  console.log(`Server is running on ${process.env.PORT} port `);
  dbConnection();
});
