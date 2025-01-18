const mongoose = require('mongoose');
require('dotenv').config();

// Define MongoDB Schema (using your original schema)
const QuizSchema = new mongoose.Schema({
    question: String,
    options: [String],
    correctAnswer: Number
});

const Quiz = mongoose.model('Quiz', QuizSchema);

async function deleteAllQuestions() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('Connected to MongoDB');

        // Count questions before deletion
        const beforeCount = await Quiz.countDocuments();
        console.log(`Questions before deletion: ${beforeCount}`);

        // Delete all questions
        await Quiz.deleteMany({});
        console.log('All questions deleted successfully');

        // Verify deletion
        const afterCount = await Quiz.countDocuments();
        console.log(`Questions after deletion: ${afterCount}`);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.connection.close();
        console.log('Database connection closed');
        process.exit(0);
    }
}

deleteAllQuestions(); 