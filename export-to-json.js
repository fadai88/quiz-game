const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');

const dbPath = path.join(__dirname, 'data', 'quiz.db');
const outputPath = path.join(__dirname, 'questions.json');

console.log('📂 Opening database at:', dbPath);

const db = new sqlite3.Database(dbPath, sqlite3.OPEN_READONLY, (err) => {
    if (err) {
        console.error('❌ Error connecting to quiz.db:', err);
        process.exit(1);
    }
    console.log('✅ Connected to quiz.db');
});

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

db.all(query, [], (err, rows) => {
    if (err) {
        console.error('❌ Error querying database:', err);
        db.close();
        process.exit(1);
    }

    console.log(`📊 Found ${rows.length} questions`);

    // Convert to the format needed for MongoDB
    const questions = rows.map(row => {
        const answers = row.answers.split('|||');
        const isCorrectArray = row.is_correct.split('|||').map(Number);
        const correctAnswerIndex = isCorrectArray.indexOf(1);

        return {
            question: row.question,
            options: answers,
            correctAnswer: correctAnswerIndex
        };
    });

    // Write to JSON file
    fs.writeFileSync(outputPath, JSON.stringify(questions, null, 2));
    console.log(`✅ Exported ${questions.length} questions to ${outputPath}`);
    console.log(`📊 File size: ${(fs.statSync(outputPath).size / 1024 / 1024).toFixed(2)} MB`);

    db.close(() => {
        console.log('🔒 Database closed');
        process.exit(0);
    });
});