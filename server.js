const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
require('dotenv').config();
const moment = require('moment');
const nodemailer = require('nodemailer'); // Import Nodemailer
const crypto = require('crypto'); // For generating verification tokens
const User = require('./models/User');
const axios = require('axios'); // Add this line at the top with other imports
const { Connection, PublicKey, SystemProgram } = require('@solana/web3.js');
const { Program } = require('@project-serum/anchor');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('Could not connect to MongoDB', err));

const Quiz = mongoose.model('Quiz', new mongoose.Schema({
    question: String,
    options: [String],
    correctAnswer: Number
}));

const gameRooms = new Map();

// Configure Nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail', // or your email service
    auth: {
        user: process.env.EMAIL_USER, // Your email address
        pass: process.env.EMAIL_PASS, // Your app password or email password
    },
});

// Create Solana connection
const connection = new Connection(process.env.SOLANA_RPC_URL);

// Initialize programId
let programId;
if (process.env.PROGRAM_ID) {
    programId = new PublicKey(process.env.PROGRAM_ID);
} else {
    console.warn('Warning: PROGRAM_ID not set in environment variables');
    // Use SystemProgram.programId instead of string
    programId = SystemProgram.programId;
}

io.on('connection', (socket) => {
    console.log('New client connected:', socket.id);

    socket.on('register', async ({ username, email, password, token }) => {
        console.log('Received token:', token); // Log the received token
        const recaptchaResponse = await verifyRecaptcha(token);
        if (!recaptchaResponse.success) {
            console.error('reCAPTCHA verification failed:', recaptchaResponse); // Log the failure
            return socket.emit('registrationFailure', 'reCAPTCHA verification failed.');
        }
        try {
            const verificationToken = crypto.randomBytes(32).toString('hex'); // Generate token
            const user = new User({ username, email, password, verificationToken, isVerified: false }); // Save user with verificationToken
            await user.save();

            // Send verification email
            const verificationUrl = `${process.env.BASE_URL}/verify-email?token=${verificationToken}`;
            await transporter.sendMail({
                to: email,
                subject: 'Email Verification',
                html: `Please verify your email by clicking <a href="${verificationUrl}">here</a>`,
            });

            console.log(`User registered: ${username}, pending verification`); // Log registration
            socket.emit('registrationSuccess');
        } catch (error) {
            socket.emit('registrationFailure', error.message);
        }
    });

    socket.on('login', async ({ username, password, token }) => {
        const recaptchaResponse = await verifyRecaptcha(token);
        if (!recaptchaResponse.success) {
            console.error('reCAPTCHA verification failed:', recaptchaResponse); // Log the failure
            return socket.emit('loginFailure', 'reCAPTCHA verification failed.');
        }
        try {
            const user = await User.findOne({ username });
            if (user && await user.matchPassword(password)) {
                if (!user.isVerified) {
                    socket.emit('loginFailure', 'Please verify your email before logging in.');
                    return;
                }
                socket.emit('loginSuccess', username);
            } else {
                socket.emit('loginFailure', 'Invalid username or password');
            }
        } catch (error) {
            socket.emit('loginFailure', error.message);
        }
    });

    socket.on('joinGame', async (username, betAmount, walletAddress) => {
        // Add debugging logs
        console.log('Join game attempt:', { username, betAmount, walletAddress });

        if (!username || !walletAddress) {
            console.log('Join game failed - missing data:', { username, walletAddress });
            socket.emit('joinGameFailure', 'You must be logged in and connect your wallet to join the game.');
            return;
        }

        try {
            const user = await User.findOne({ username });
            if (!user) {
                console.log('User not found:', username);
                socket.emit('joinGameFailure', 'User not found.');
                return;
            }
            if (!user.isVerified) {
                socket.emit('joinGameFailure', 'Please verify your email before joining the game.');
                return;
            }
            if (user.virtualBalance < betAmount) {
                socket.emit('joinGameFailure', `Insufficient virtual balance. You need $${betAmount} to join the game.`);
                return;
            }
            const updatedUser = await User.findOneAndUpdate(
                { username }, 
                { $inc: { gamesPlayed: 1, virtualBalance: -betAmount } },
                { new: true }
            );
            socket.emit('balanceUpdate', updatedUser.virtualBalance);

            console.log(`${username} (${socket.id}) is trying to join a game`);
            let roomId;
            let joinedExistingRoom = false;

            for (const [id, room] of gameRooms.entries()) {
                if (room.players.length < 2 && room.betAmount === betAmount) {
                    roomId = id;
                    joinedExistingRoom = true;
                    break;
                }
            }

            if (!roomId) {
                roomId = generateRoomId();
                gameRooms.set(roomId, { 
                    players: [], 
                    questions: [], 
                    currentQuestionIndex: 0,
                    answersReceived: 0,
                    betAmount: betAmount,
                    waitingTimeout: setTimeout(async () => {  // Add timeout for single player mode
                        const room = gameRooms.get(roomId);
                        if (room && room.players.length === 1) {
                            console.log(`Starting single player mode for ${username} in room ${roomId}`);
                            await startSinglePlayerGame(roomId);
                        }
                    }, 30000)  // 30 seconds wait time
                });
                console.log(`Created new room: ${roomId}`);
            }

            const room = gameRooms.get(roomId);
            room.players.push({ id: socket.id, username, score: 0 });

            // Comment out Solana integration for now
            /*
            if (!joinedExistingRoom) {
                await program.rpc.initializeGame(
                    new BN(betAmount),
                    roomId,
                    {
                        accounts: {
                            creator: new PublicKey(walletAddress),
                            game: gameAccount,
                            systemProgram: SystemProgram.programId,
                        },
                    }
                );
            } else {
                await program.rpc.joinGame(
                    roomId,
                    {
                        accounts: {
                            game: gameAccount,
                            player: new PublicKey(walletAddress),
                            playerTokenAccount: playerTokenAccount,
                            gameVault: gameVault,
                            tokenProgram: TOKEN_PROGRAM_ID,
                        },
                    }
                );
            }
            */

            // The rest of your game logic
            socket.join(roomId);
            socket.emit('gameJoined', roomId);

            console.log(`Player ${username} (${socket.id}) joined room ${roomId}`);
            console.log(`Room ${roomId} now has ${room.players.length} player(s)`);

            if (room.players.length === 2) {
                clearTimeout(room.waitingTimeout);  // Clear timeout when second player joins
                console.log(`Starting game in room ${roomId}`);
                startGame(roomId);
            } else if (joinedExistingRoom) {
                console.log(`Notifying other player in room ${roomId} that ${username} joined`);
                socket.to(roomId).emit('playerJoined', username);
            }

            // Notify all players in the lobby
            socket.broadcast.emit('playerJoined', username);

            // Send the room ID back to the player
            socket.emit('roomId', roomId);
        } catch (error) {
            console.error('Error joining game:', error);
            socket.emit('joinGameFailure', 'Failed to join game. Please try again.');
        }
    });

    socket.on('submitAnswer', async ({ roomId, answer, responseTime, username }) => {
        const room = gameRooms.get(roomId);
        if (!room) return;

        const player = room.players.find(p => p.username === username);
        if (!player) return;

        player.totalResponseTime = (player.totalResponseTime || 0) + responseTime;
        player.lastAnswer = answer; // Store the player's answer

        const currentQuestion = room.questions[room.currentQuestionIndex];
        const isCorrect = answer === currentQuestion.correctAnswer;

        if (isCorrect) {
            player.score += 1;
            try {
                await User.findOneAndUpdate(
                    { username },
                    { 
                        $inc: { 
                            correctAnswers: 1,
                            totalPoints: 1
                        } 
                    }
                );
            } catch (error) {
                console.error('Error updating user stats:', error);
            }
        }

        player.answered = true;

        // Send result only to the player who answered
        socket.emit('answerResult', {
            username: player.username,
            isCorrect,
            correctAnswer: currentQuestion.correctAnswer
        });

        if (room.players.every(p => p.answered)) {
            // When all players have answered, send the complete results to everyone
            io.to(roomId).emit('roundComplete', {
                correctAnswer: currentQuestion.correctAnswer,
                playerResults: room.players.map(p => ({
                    username: p.username,
                    isCorrect: p.lastAnswer === currentQuestion.correctAnswer,
                    answer: p.lastAnswer
                }))
            });
            completeQuestion(roomId);
        } else {
            // Just update that a player has answered without revealing the answer
            socket.to(roomId).emit('playerAnswered', username);
        }
    });

    socket.on('getLeaderboard', async () => {
        try {
            const leaderboard = await User.find({}, 'username correctAnswers gamesPlayed totalPoints')
                .sort({ totalPoints: -1 })
                .limit(10);
            socket.emit('leaderboardData', leaderboard);
        } catch (error) {
            console.error('Error fetching leaderboard:', error);
            socket.emit('leaderboardError', 'Failed to fetch leaderboard data');
        }
    });

    socket.on('disconnect', () => {
        console.log('Client disconnected:', socket.id);
        for (const [roomId, room] of gameRooms.entries()) {
            const playerIndex = room.players.findIndex(p => p.id === socket.id);
            if (playerIndex !== -1) {
                const disconnectedPlayer = room.players[playerIndex];
                room.players.splice(playerIndex, 1);
                console.log(`Player ${disconnectedPlayer.username} left room ${roomId}`);
                if (room.players.length === 0) {
                    console.log(`Deleting empty room ${roomId}`);
                    gameRooms.delete(roomId);
                } else {
                    console.log(`Notifying remaining player in room ${roomId}`);
                    io.to(roomId).emit('playerLeft', disconnectedPlayer.username);
                }
                break;
            }
        }
    });
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (user && await user.matchPassword(password)) {
            res.json({ 
                success: true, 
                message: 'Login successful', 
                username: user.username,
                virtualBalance: user.virtualBalance
            });
        } else {
            res.json({ success: false, message: 'Invalid credentials' });
        }
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/balance/:username', async (req, res) => {
    try {
        const user = await User.findOne({ username: req.params.username });
        if (user) {
            res.json({ balance: user.virtualBalance });
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/topup/:username', async (req, res) => {
    try {
        const user = await User.findOneAndUpdate(
            { username: req.params.username },
            { $inc: { virtualBalance: 10 } },
            { new: true }
        );
        if (user) {
            res.json({ success: true, newBalance: user.virtualBalance });
        } else {
            res.status(404).json({ success: false, message: 'User not found' });
        }
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

async function startGame(roomId) {
    console.log(`Attempting to start game in room ${roomId}`);
    const room = gameRooms.get(roomId);
    if (!room) {
        console.log(`Room ${roomId} not found when trying to start game`);
        return;
    }

    room.players.forEach(player => player.score = 0);

    try {
        // Fetch 7 random questions from MongoDB
        room.questions = await Quiz.aggregate([{ $sample: { size: 7 } }]);
        console.log(`Fetched ${room.questions.length} questions for room ${roomId}`);
        io.to(roomId).emit('gameStart', { players: room.players, questionCount: room.questions.length });
        startNextQuestion(roomId);
    } catch (error) {
        console.error('Error starting game:', error);
        io.to(roomId).emit('gameError', 'Failed to start the game. Please try again.');
    }
}

function startNextQuestion(roomId) {
    const room = gameRooms.get(roomId);
    if (!room) {
        console.log(`Room ${roomId} not found when trying to start next question`);
        return;
    }

    const currentQuestion = room.questions[room.currentQuestionIndex];
    const questionStartTime = moment();

    io.to(roomId).emit('nextQuestion', {
        question: currentQuestion.question,
        options: currentQuestion.options,
        questionNumber: room.currentQuestionIndex + 1,
        totalQuestions: room.questions.length,
        questionStartTime: questionStartTime.valueOf(),
        correctAnswerIndex: currentQuestion.correctAnswer
    });

    room.questionStartTime = questionStartTime;
    room.answersReceived = 0;

    // Clear any existing timeout
    if (room.questionTimeout) {
        clearTimeout(room.questionTimeout);
    }

    // Set a new timeout for this question
    room.questionTimeout = setTimeout(() => {
        completeQuestion(roomId);
    }, 10000); // 10 seconds for each question
}

function completeQuestion(roomId) {
    const room = gameRooms.get(roomId);
    if (!room) return;

    // Reset answered status for next question
    room.players.forEach(player => {
        player.answered = false;
    });

    io.to(roomId).emit('updateScores', room.players.map(p => ({ 
        username: p.username, 
        score: p.score, 
        totalResponseTime: p.totalResponseTime || 0
    })));

    if (room.questionTimeout) {
        clearTimeout(room.questionTimeout);
    }

    room.currentQuestionIndex += 1;
    room.answersReceived = 0;

    if (room.currentQuestionIndex < room.questions.length) {
        setTimeout(() => {
            startNextQuestion(roomId);
        }, 1000);
    } else {
        console.log(`Game over in room ${roomId}`);
        const isSinglePlayer = room.players.length === 1;
        let winner = null;

        if (isSinglePlayer) {
            const player = room.players[0];
            winner = player.score >= 5 ? player.username : null;
            console.log(`Single player game ended. Player ${player.username} scored ${player.score}/7 ${winner ? '(WIN)' : '(LOSS)'}`);
        } else {
            const sortedPlayers = [...room.players].sort((a, b) => {
                if (b.score !== a.score) {
                    return b.score - a.score;
                }
                return (a.totalResponseTime || 0) - (b.totalResponseTime || 0);
            });

            // Log detailed game results
            console.log('Game Results:');
            sortedPlayers.forEach(player => {
                console.log(`Player ${player.username}: ${player.score} correct answers, Response time: ${player.totalResponseTime}ms`);
            });

            if (sortedPlayers[0].score > sortedPlayers[1].score) {
                winner = sortedPlayers[0].username;
                console.log(`Winner by score: ${winner} (${sortedPlayers[0].score} vs ${sortedPlayers[1].score})`);
            } else if (sortedPlayers[0].score === sortedPlayers[1].score) {
                winner = sortedPlayers[0].totalResponseTime <= sortedPlayers[1].totalResponseTime ? 
                    sortedPlayers[0].username : sortedPlayers[1].username;
                console.log(`Tie on score (${sortedPlayers[0].score}), Winner by response time: ${winner}`);
                console.log(`Response times: ${sortedPlayers[0].username}: ${sortedPlayers[0].totalResponseTime}ms, ${sortedPlayers[1].username}: ${sortedPlayers[1].totalResponseTime}ms`);
            }
        }

        // Update winner's balance if there is a winner
        if (winner) {
            User.findOneAndUpdate(
                { username: winner },
                { $inc: { virtualBalance: room.betAmount * 1.8 } },
                { new: true }
            ).then(updatedUser => {
                io.to(roomId).emit('gameOver', {
                    players: room.players.map(p => ({ 
                        username: p.username, 
                        score: p.score, 
                        totalResponseTime: p.totalResponseTime || 0
                    })),
                    winner: winner,
                    betAmount: room.betAmount,
                    winnerBalance: updatedUser.virtualBalance,
                    singlePlayerMode: isSinglePlayer
                });
            }).catch(error => {
                console.error('Error updating winner balance:', error);
            });
        } else {
            io.to(roomId).emit('gameOver', {
                players: room.players.map(p => ({ 
                    username: p.username, 
                    score: p.score, 
                    totalResponseTime: p.totalResponseTime || 0
                })),
                winner: null,
                betAmount: room.betAmount,
                singlePlayerMode: isSinglePlayer
            });
        }

        gameRooms.delete(roomId);
    }
}

// Remove or simplify the determineWinner function since the logic is now in completeQuestion
function determineWinner(players) {
    const sortedPlayers = [...players].sort((a, b) => {
        if (b.score !== a.score) {
            return b.score - a.score;
        }
        return (a.totalResponseTime || 0) - (b.totalResponseTime || 0);
    });

    return sortedPlayers[0].username;
}

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// Function to generate a unique room ID
function generateRoomId() {
    return Math.random().toString(36).substring(7);
}

app.get('/join', (req, res) => {
    const roomId = req.query.roomId;
    // Logic to add the player to the specified room
    // ...
});

// Email verification endpoint
app.get('/verify-email', async (req, res) => {
    const { token } = req.query;

    try {
        const user = await User.findOne({ verificationToken: token });
        if (!user) {
            return res.status(400).send('Invalid verification token');
        }

        user.isVerified = true;
        user.verificationToken = undefined; // Clear the token
        await user.save();

        console.log(`User verified successfully: ${user.username}`); // Log verification
        res.send('Email verified successfully! You can now join the game.');
    } catch (error) {
        res.status(500).send('Error verifying email');
    }
});

app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        const verificationToken = crypto.randomBytes(32).toString('hex'); // Generate token
        const user = new User({ username, email, password, verificationToken, isVerified: false }); // Save user with verificationToken
        await user.save();

        // Send verification email
        const verificationUrl = `${process.env.BASE_URL}/verify-email?token=${verificationToken}`;
        await transporter.sendMail({
            to: email,
            subject: 'Email Verification',
            html: `Please verify your email by clicking <a href="${verificationUrl}">here</a>`,
        });

        console.log(`User registered: ${username}, pending verification`); // Log registration
        res.status(201).json({ success: true, message: 'Registration successful! Please check your email to verify your account.' });
    } catch (error) {
        res.status(400).json({ success: false, message: error.message });
    }
});

// Function to verify reCAPTCHA token
async function verifyRecaptcha(token) {
    const secretKey = process.env.RECAPTCHA_SECRET_KEY; // Ensure this is set correctly
    const response = await axios.post(`https://www.google.com/recaptcha/api/siteverify`, null, {
        params: {
            secret: secretKey,
            response: token
        }
    });
    console.log('reCAPTCHA verification response:', response.data); // Log the verification response
    return response.data;
}

// Add new function for single player mode
async function startSinglePlayerGame(roomId) {
    const room = gameRooms.get(roomId);
    if (!room) return;

    try {
        room.questions = await Quiz.aggregate([{ $sample: { size: 7 } }]);
        const player = room.players[0];
        
        io.to(roomId).emit('gameStart', { 
            players: room.players, 
            questionCount: room.questions.length,
            singlePlayerMode: true 
        });

        startNextQuestion(roomId);
    } catch (error) {
        console.error('Error starting single player game:', error);
        io.to(roomId).emit('gameError', 'Failed to start the game. Please try again.');
    }
}




/*
Great! Yes, using the System Program ID (11111111111111111111111111111111) as a placeholder is a good way to start development.
Now that your server is running, here is what you might want to do next:
Test your basic MongoDB functionality (quiz questions, user registration, etc.)
When you're ready to implement the actual Solana integration:
Create your own Solana program (smart contract)
Deploy it to devnet
Replace the dummy program ID with your actual program ID
Implement the token (USDC/USDT) integration
Would you like me to help you with any of these next steps? For example:
Testing the existing quiz functionality
Creating and deploying a Solana program
Setting up token integration
Let me know what you'd like to focus on next!
*/