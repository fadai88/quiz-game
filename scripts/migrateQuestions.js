const sqlite3 = require('sqlite3').verbose();
const mongoose = require('mongoose');
const path = require('path');
require('dotenv').config();

// MongoDB Quiz model
const Quiz = mongoose.model('Quiz', new mongoose.Schema({
    question: String,
    options: [String],
    correctAnswer: Number
}));

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
    .then(() => {
        console.log('Connected to MongoDB');
        migrateQuestions();
    }).catch(err => {
        console.error('MongoDB connection error:', err);
    });

function migrateQuestions() {
    const dbPath = path.join(__dirname, '..', 'data', 'quiz.db');
    console.log('Attempting to open database at:', dbPath);

    const db = new sqlite3.Database(dbPath, (err) => {
        if (err) {
            console.error('Error connecting to quiz.db:', err);
            process.exit(1);
        }
        console.log('Connected to quiz.db');
    });

    // First, let's examine the structure of a few rows
    db.all("SELECT * FROM questions LIMIT 5", [], (err, sampleRows) => {
        if (err) {
            console.error('Error reading sample questions:', err);
            return;
        }
        console.log('Sample row structure:', sampleRows[0]);
    });

    db.all("SELECT * FROM questions", [], async (err, rows) => {
        if (err) {
            console.error('Error reading questions:', err);
            process.exit(1);
        }

        try {
            console.log(`Found ${rows ? rows.length : 0} questions in SQLite database`);

            if (!rows || rows.length === 0) {
                console.error('No questions found in SQLite database');
                process.exit(1);
            }

            await Quiz.deleteMany({});
            console.log('Cleared existing questions from MongoDB');

            // Convert and validate each question
            const questions = rows.map(row => {
                // Ensure correct_answer is a valid number
                let correctAnswer = parseInt(row.correct_answer);
                if (isNaN(correctAnswer)) {
                    console.warn(`Invalid correct_answer for question: "${row.question}". Setting to 0.`);
                    correctAnswer = 0;
                }
                // Adjust to 0-based index if needed
                correctAnswer = correctAnswer > 0 ? correctAnswer - 1 : 0;

                return {
                    question: row.question,
                    options: [
                        row.option1 || 'Option 1',
                        row.option2 || 'Option 2',
                        row.option3 || 'Option 3',
                        row.option4 || 'Option 4'
                    ],
                    correctAnswer: correctAnswer
                };
            });

            // Insert questions in smaller batches
            const batchSize = 100;
            for (let i = 0; i < questions.length; i += batchSize) {
                const batch = questions.slice(i, i + batchSize);
                await Quiz.insertMany(batch);
                console.log(`Migrated questions ${i + 1} to ${Math.min(i + batchSize, questions.length)}`);
            }

            console.log(`Successfully migrated ${questions.length} questions to MongoDB`);
        } catch (error) {
            console.error('Error migrating questions:', error);
            if (error.errors) {
                // Log detailed validation errors
                Object.keys(error.errors).forEach(key => {
                    console.error(`Validation error for ${key}:`, error.errors[key].message);
                });
            }
        } finally {
            mongoose.connection.close();
            db.close();
            process.exit(0);
        }
    });
} 