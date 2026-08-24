import mongoose from "mongoose";

const dbConnection = async () => {
  try {
    const mongoConnection = await mongoose.connect(process.env.MONGO_URI);
    console.log("DB connected");
  } catch (err) {
    console.log("Error occur while connecting to database", err);
  }
};

export { dbConnection };
