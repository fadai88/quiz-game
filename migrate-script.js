const sqlite3 = require('sqlite3').verbose();
const mongoose = require('mongoose');
const path = require('path');
require('dotenv').config();

// MongoDB Quiz model
const QuizSchema = new mongoose.Schema({
    question: String,
    options: [String],
    correctAnswer: Number
});

const Quiz = mongoose.model('Quiz', QuizSchema);

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
    .then(() => {
        console.log('✅ Connected to MongoDB');
        migrateQuestions();
    })
    .catch(err => {
        console.error('❌ MongoDB connection error:', err);
        process.exit(1);
    });

function migrateQuestions() {
    const dbPath = path.join(__dirname, 'data', 'quiz.db');
    console.log('📂 Opening database at:', dbPath);

    const db = new sqlite3.Database(dbPath, sqlite3.OPEN_READONLY, (err) => {
        if (err) {
            console.error('❌ Error connecting to quiz.db:', err);
            process.exit(1);
        }
        console.log('✅ Connected to quiz.db');
    });

    // First, examine a sample to verify structure
    db.all("SELECT * FROM questions LIMIT 2", [], (err, sampleQuestions) => {
        if (err) {
            console.error('❌ Error reading sample questions:', err);
            db.close();
            mongoose.connection.close();
            process.exit(1);
        }
        console.log('📊 Sample question:', sampleQuestions[0]);
    });

    db.all("SELECT * FROM answers WHERE question_id = (SELECT question_id FROM questions LIMIT 1)", [], (err, sampleAnswers) => {
        if (err) {
            console.error('❌ Error reading sample answers:', err);
        } else {
            console.log('📊 Sample answers:', sampleAnswers);
        }
    });

    // Main migration query - JOIN questions with answers
    const query = `
        SELECT 
            q.question_id, 
            q.question, 
            GROUP_CONCAT(a.answer, '|||') as answers,
            GROUP_CONCAT(a.is_correct, '|||') as is_correct
        FROM questions q
        JOIN answers a ON q.question_id = a.question_id
        GROUP BY q.question_id
        ORDER BY q.question_id
    `;

    db.all(query, [], async (err, rows) => {
        if (err) {
            console.error('❌ Error executing migration query:', err);
            db.close();
            mongoose.connection.close();
            process.exit(1);
        }

        try {
            console.log(`\n📊 Found ${rows ? rows.length : 0} questions in SQLite database`);

            if (!rows || rows.length === 0) {
                console.error('❌ No questions found in SQLite database');
                db.close();
                mongoose.connection.close();
                process.exit(1);
            }

            // Clear existing questions from MongoDB
            const deleteResult = await Quiz.deleteMany({});
            console.log(`🗑️  Cleared ${deleteResult.deletedCount} existing questions from MongoDB`);

            // Convert and validate each question
            const questions = [];
            let skippedCount = 0;

            for (const row of rows) {
                try {
                    const answers = row.answers.split('|||');
                    const isCorrectArray = row.is_correct.split('|||').map(Number);
                    const correctAnswerIndex = isCorrectArray.indexOf(1);

                    // Validation
                    if (correctAnswerIndex === -1) {
                        console.warn(`⚠️  Skipping question (no correct answer): "${row.question.substring(0, 50)}..."`);
                        skippedCount++;
                        continue;
                    }

                    if (answers.length < 2) {
                        console.warn(`⚠️  Skipping question (not enough answers): "${row.question.substring(0, 50)}..."`);
                        skippedCount++;
                        continue;
                    }

                    questions.push({
                        question: row.question,
                        options: answers,
                        correctAnswer: correctAnswerIndex
                    });
                } catch (error) {
                    console.error(`❌ Error processing question ID ${row.question_id}:`, error.message);
                    skippedCount++;
                }
            }

            console.log(`\n📝 Prepared ${questions.length} valid questions for migration`);
            if (skippedCount > 0) {
                console.log(`⚠️  Skipped ${skippedCount} invalid questions`);
            }

            // Insert questions in batches
            const batchSize = 100;
            let insertedCount = 0;

            for (let i = 0; i < questions.length; i += batchSize) {
                const batch = questions.slice(i, i + batchSize);
                await Quiz.insertMany(batch);
                insertedCount += batch.length;
                console.log(`✅ Migrated questions ${i + 1} to ${Math.min(i + batchSize, questions.length)} (${insertedCount}/${questions.length})`);
            }

            console.log(`\n🎉 Successfully migrated ${insertedCount} questions to MongoDB!`);

            // Verify the migration
            const count = await Quiz.countDocuments();
            console.log(`✅ Verification: ${count} questions now in MongoDB`);

        } catch (error) {
            console.error('❌ Error during migration:', error);
            if (error.errors) {
                Object.keys(error.errors).forEach(key => {
                    console.error(`  Validation error for ${key}:`, error.errors[key].message);
                });
            }
        } finally {
            db.close(() => console.log('🔒 SQLite connection closed'));
            mongoose.connection.close(() => {
                console.log('🔒 MongoDB connection closed');
                process.exit(0);
            });
        }
    });
}