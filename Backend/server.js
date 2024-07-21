import express from 'express';
import userRouter from './routes/users.js';
import gauthRouter from './routes/gauth.js';
import courseRouter from './routes/courses.js';
import reviewRouter from './routes/reviews.js';
import tagRouter from './routes/tags.js';
const app = express()
app.use(express.json());
app.use('/api',userRouter)
app.use('/api',gauthRouter)
app.use('/api/courses',courseRouter)
app.use('/api/reviews',reviewRouter)
app.use('/api/tags',tagRouter)

app.listen(process.env.PORT || 4000)