const mongoose = require('mongoose');
require('dotenv').config();

const QuizSchema = new mongoose.Schema({
    question: String,
    options: [String],
    correctAnswer: Number
});

const Quiz = mongoose.model('Quiz', QuizSchema);

async function findQuestions(questionIds) {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('Connected to MongoDB');

        // First, get a sample question to see the structure
        const questions = await Quiz.find().skip(questionIds[0] - 1).limit(1);
        
        questionIds.forEach(async (id, index) => {
            // Get question at specific index (id - 1 because array is 0-based)
            const question = await Quiz.find().skip(id - 1).limit(1);
            
            if (question && question[0]) {
                console.log(`\nQuestion ID ${id}:`);
                console.log('Question:', question[0].question);
                console.log('Options:');
                question[0].options.forEach((opt, i) => {
                    console.log(`${i + 1}. ${opt}${i === question[0].correctAnswer ? ' ✓' : ''}`);
                });
                console.log('-------------------');
            } else {
                console.log(`\nQuestion ID ${id} not found`);
            }
        });

    } catch (error) {
        console.error('Error:', error);
    } finally {
        // Wait a bit before closing to allow all queries to complete
        setTimeout(async () => {
            await mongoose.connection.close();
            console.log('\nDatabase connection closed');
            process.exit(0);
        }, 1000);
    }
}

// Pass the question IDs you want to find
findQuestions([779, 786]); 