const mongoose = require('mongoose');
require('dotenv').config();

mongoose.connect(process.env.MONGODB_URI)
    .then(async () => {
        console.log('Connected to MongoDB');
        
        try {
            // Get the users collection
            const collection = mongoose.connection.collection('users');
            
            // Drop all indexes
            await collection.dropIndexes();
            console.log('Dropped all indexes');

            // Remove any documents with null walletAddress
            await collection.deleteMany({ 
                $or: [
                    { walletAddress: null },
                    { walletAddress: { $exists: false } }
                ]
            });
            console.log('Removed documents with null walletAddress');
            
            // Create new index only for walletAddress
            await collection.createIndex({ walletAddress: 1 }, { 
                unique: true,
                sparse: true  // Only index documents that have walletAddress field
            });
            console.log('Created new walletAddress index');
            
            mongoose.connection.close();
            console.log('Done');
        } catch (error) {
            console.error('Error:', error);
            mongoose.connection.close();
        }
    })
    .catch(err => console.error('Could not connect to MongoDB', err)); 