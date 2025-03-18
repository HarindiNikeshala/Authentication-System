import express from 'express';
import cors from 'cors';
import 'dotenv/config';
import cookieParser from 'cookie-parser';
import connectDB from './config/mongodb.js';
import authRouter from './routes/authroutes.js';
import userRouter from './routes/userRoutes.js';

const app = express();
const port = process.env.PORT || 4000;
connectDB();

app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: process.env.FRONTEND_URL, credentials: true }));

//API ENDPOINTS
app.get('/', (req, res) => {
  res.send('API working now');
});

app.use('/api/auth', authRouter);
app.use('/api/user', userRouter);

app.listen(port, () => {
  console.log(`Server is running on port: ${port}`);
});