import React, { useState, useEffect } from 'react';
import { Alert, AlertDescription } from '@/components/ui/alert';

const GameWallet = ({ onJoinGame }) => {
    const [walletAddress, setWalletAddress] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState(null);
    const [balance, setBalance] = useState(0);

    useEffect(() => {
        // Check if wallet is already connected
        const savedWallet = localStorage.getItem('walletAddress');
        if (savedWallet) {
            setWalletAddress(savedWallet);
            fetchBalance(savedWallet);
        }
    }, []);

    const fetchBalance = async (address) => {
        try {
            const response = await fetch(`/api/balance/${address}`);
            const data = await response.json();
            if (data.balance) {
                setBalance(data.balance);
            }
        } catch (error) {
            console.error('Error fetching balance:', error);
        }
    };

    const connectWallet = async () => {
        try {
            setError(null);
            setIsLoading(true);

            if (!window.solana || !window.solana.isPhantom) {
                throw new Error('Please install Phantom wallet!');
            }

            const resp = await window.solana.connect();
            const publicKey = resp.publicKey.toString();
            
            // Sign message to verify wallet ownership
            const message = `Login to Trivia Game: ${Date.now()}`;
            const encodedMessage = new TextEncoder().encode(message);
            const signedData = await window.solana.signMessage(encodedMessage, 'utf8');
            const signature = btoa(String.fromCharCode.apply(null, signedData.signature));

            // Verify wallet connection server-side
            const verifyResponse = await fetch('/api/verify-wallet', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    walletAddress: publicKey,
                    signature,
                    message
                })
            });

            if (!verifyResponse.ok) {
                throw new Error('Failed to verify wallet');
            }

            setWalletAddress(publicKey);
            localStorage.setItem('walletAddress', publicKey);
            fetchBalance(publicKey);

        } catch (err) {
            setError(err.message);
            console.error('Wallet connection error:', err);
        } finally {
            setIsLoading(false);
        }
    };

    const handleJoinGame = async (betAmount) => {
        if (!walletAddress) return;
        
        try {
            setIsLoading(true);
            setError(null);

            // For now, we'll simulate a transaction signature
            // In production, this would be a real Solana transaction
            const mockSignature = 'mock_' + Date.now();

            // Call the join game callback
            onJoinGame(betAmount, mockSignature);

        } catch (error) {
            setError('Failed to process payment. Please try again.');
            console.error('Error joining game:', error);
        } finally {
            setIsLoading(false);
        }
    };

    const disconnectWallet = () => {
        localStorage.removeItem('walletAddress');
        setWalletAddress(null);
        setBalance(0);
    };

    return (
        <div className="p-4 space-y-4">
            <div className="flex justify-between items-center">
                {!walletAddress ? (
                    <button
                        onClick={connectWallet}
                        disabled={isLoading}
                        className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 disabled:opacity-50"
                    >
                        {isLoading ? 'Connecting...' : 'Connect Phantom Wallet'}
                    </button>
                ) : (
                    <div className="flex items-center space-x-4">
                        <span className="text-sm">
                            {`${walletAddress.slice(0, 4)}...${walletAddress.slice(-4)}`}
                        </span>
                        <button
                            onClick={disconnectWallet}
                            className="px-3 py-1 bg-red-500 text-white text-sm rounded hover:bg-red-600"
                        >
                            Disconnect
                        </button>
                    </div>
                )}
                
                {walletAddress && (
                    <div className="text-right">
                        <p className="text-sm text-gray-600">Balance</p>
                        <p className="text-lg font-bold">${balance.toFixed(2)}</p>
                    </div>
                )}
            </div>

            {error && (
                <Alert variant="destructive">
                    <AlertDescription>{error}</AlertDescription>
                </Alert>
            )}

            {walletAddress && (
                <div className="space-y-4">
                    <select 
                        className="w-full p-2 border rounded bg-white"
                        onChange={(e) => handleJoinGame(Number(e.target.value))}
                        disabled={isLoading}
                        defaultValue=""
                    >
                        <option value="" disabled>Select Bet Amount</option>
                        <option value="3">$3 USDC</option>
                        <option value="10">$10 USDC</option>
                        <option value="15">$15 USDC</option>
                        <option value="20">$20 USDC</option>
                        <option value="30">$30 USDC</option>
                    </select>

                    {isLoading && (
                        <div className="text-center text-gray-600">
                            Processing payment...
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};

export default GameWallet;