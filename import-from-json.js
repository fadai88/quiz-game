const mongoose = require('mongoose');
const fs = require('fs');
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
        importQuestions();
    })
    .catch(err => {
        console.error('❌ MongoDB connection error:', err);
        process.exit(1);
    });

async function importQuestions() {
    try {
        const jsonPath = path.join(__dirname, 'questions.json');
        console.log('📂 Reading questions from:', jsonPath);

        // Check if file exists
        if (!fs.existsSync(jsonPath)) {
            console.error('❌ questions.json not found!');
            console.error('   Run: node export-to-json.js first');
            process.exit(1);
        }

        // Read and parse JSON
        const jsonData = fs.readFileSync(jsonPath, 'utf8');
        const questions = JSON.parse(jsonData);
        
        console.log(`📊 Found ${questions.length} questions in JSON file`);

        if (questions.length === 0) {
            console.error('❌ No questions found in JSON file');
            process.exit(1);
        }

        // Clear existing questions
        const deleteResult = await Quiz.deleteMany({});
        console.log(`🗑️  Cleared ${deleteResult.deletedCount} existing questions from MongoDB`);

        // Validate and clean data
        let validQuestions = [];
        let skippedCount = 0;

        for (let i = 0; i < questions.length; i++) {
            const q = questions[i];
            
            // Validation
            if (!q.question || !q.options || !Array.isArray(q.options)) {
                console.warn(`⚠️  Skipping invalid question at index ${i}`);
                skippedCount++;
                continue;
            }

            if (q.correctAnswer === -1 || q.correctAnswer >= q.options.length) {
                console.warn(`⚠️  Skipping question with invalid correct answer: "${q.question.substring(0, 50)}..."`);
                skippedCount++;
                continue;
            }

            validQuestions.push(q);
        }

        console.log(`📝 Validated ${validQuestions.length} questions (skipped ${skippedCount})`);

        // Insert in batches
        const batchSize = 100;
        let insertedCount = 0;

        for (let i = 0; i < validQuestions.length; i += batchSize) {
            const batch = validQuestions.slice(i, i + batchSize);
            await Quiz.insertMany(batch);
            insertedCount += batch.length;
            
            const progress = Math.floor((insertedCount / validQuestions.length) * 100);
            console.log(`✅ Progress: ${insertedCount}/${validQuestions.length} (${progress}%)`);
        }

        // Verify
        const finalCount = await Quiz.countDocuments();
        console.log(`\n🎉 Successfully imported ${insertedCount} questions to MongoDB!`);
        console.log(`✅ Verification: ${finalCount} questions in database`);

        if (finalCount !== insertedCount) {
            console.warn(`⚠️  Warning: Expected ${insertedCount} but found ${finalCount} in database`);
        }

    } catch (error) {
        console.error('❌ Error during import:', error);
        if (error.errors) {
            Object.keys(error.errors).forEach(key => {
                console.error(`  Validation error for ${key}:`, error.errors[key].message);
            });
        }
    } finally {
        await mongoose.connection.close();
        console.log('🔒 MongoDB connection closed');
        process.exit(0);
    }
}