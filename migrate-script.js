const sqlite3 = require('sqlite3').verbose();
const mongoose = require('mongoose');
require('dotenv').config();

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('Could not connect to MongoDB', err));

// Define MongoDB Schema
const QuizSchema = new mongoose.Schema({
    question: String,
    options: [String],
    correctAnswer: Number
});

const Quiz = mongoose.model('Quiz', QuizSchema);

// SQLite connection
let db = new sqlite3.Database('./data/quiz.db', sqlite3.OPEN_READONLY, (err) => {
    if (err) {
        console.error(err.message);
    }
    console.log('Connected to the quiz database.');
});

// Migration function
function migrateData() {
    db.all(`SELECT q.question_id, q.question, 
            GROUP_CONCAT(a.answer, '|') as answers,
            GROUP_CONCAT(a.is_correct, '|') as is_correct
            FROM questions q
            JOIN answers a ON q.question_id = a.question_id
            GROUP BY q.question_id`, [], async (err, rows) => {
        if (err) {
            throw err;
        }
        
        for (const row of rows) {
            const answers = row.answers.split('|');
            const isCorrect = row.is_correct.split('|').map(Number);
            const correctAnswerIndex = isCorrect.indexOf(1);

            const quizQuestion = new Quiz({
                question: row.question,
                options: answers,
                correctAnswer: correctAnswerIndex
            });

            try {
                await quizQuestion.save();
                console.log(`Migrated question: ${row.question}`);
            } catch (error) {
                console.error(`Error migrating question: ${row.question}`, error);
            }
        }

        console.log('Migration completed');
        mongoose.connection.close();
        db.close();
    });
}

migrateData();