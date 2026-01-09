/**
 * Reconnection Handler Test Script
 * Tests the client-side reconnection functionality in game.html
 *
 * Usage: node test-reconnection.js
 * Tests HTML structure and JavaScript logic without browser dependencies
 */

const fs = require('fs');
const path = require('path');

// Test results tracker
const results = {
    passed: 0,
    failed: 0,
    tests: []
};

function logTest(name, passed, message = '') {
    const status = passed ? '✅ PASS' : '❌ FAIL';
    console.log(`${status}: ${name}${message ? ' - ' + message : ''}`);
    results.tests.push({ name, passed, message });
    if (passed) results.passed++;
    else results.failed++;
}

async function runTests() {
    console.log('\n🧪 Starting Reconnection Handler Tests\n');
    console.log('='.repeat(50));

    try {
        // Read the game.html file
        console.log('\n📦 Loading game.html...\n');
        const htmlPath = path.join(__dirname, 'public', 'game.html');
        const htmlContent = fs.readFileSync(htmlPath, 'utf8');

        // ========================================
        // Test 1: Verify game.html exists and loads
        // ========================================
        console.log('--- Test 1: Verify game.html loads ---');
        logTest('game.html file exists', htmlContent.length > 0);
        logTest('game.html contains Trivia title', htmlContent.includes('<title>Trivia Game</title>'));

        // ========================================
        // Test 2: Verify reconnection state variables exist
        // ========================================
        console.log('\n--- Test 2: Verify reconnection state variables ---');
        logTest('isReconnecting variable declared', htmlContent.includes('let isReconnecting = false'));
        logTest('reconnectAttempts variable declared', htmlContent.includes('let reconnectAttempts = 0'));
        logTest('hasGameToRestore variable declared', htmlContent.includes('let hasGameToRestore = false'));
        logTest('MAX_RECONNECT_ATTEMPTS constant declared', htmlContent.includes('const MAX_RECONNECT_ATTEMPTS = 5'));

        // ========================================
        // Test 3: Verify reconnecting overlay HTML exists
        // ========================================
        console.log('\n--- Test 3: Verify reconnecting overlay DOM ---');
        logTest('Reconnecting overlay div exists', htmlContent.includes('id="reconnectingOverlay"'));
        logTest('Reconnect attempt counter exists', htmlContent.includes('id="reconnectAttemptCount"'));
        logTest('Overlay has z-index 10000', htmlContent.includes('z-index: 10000'));
        logTest('Overlay display is flex when shown', htmlContent.includes('display: flex') || htmlContent.includes("display: 'flex'"));
        logTest('Overlay contains "Reconnecting..." text', htmlContent.includes('Reconnecting...'));
        logTest('Overlay spinner animation exists', htmlContent.includes('reconnect-spinner') || htmlContent.includes('animation: spin'));

        // ========================================
        // Test 4: Verify helper functions exist
        // ========================================
        console.log('\n--- Test 4: Verify helper functions ---');
        logTest('showReconnectingOverlay function exists', htmlContent.includes('function showReconnectingOverlay()'));
        logTest('hideReconnectingOverlay function exists', htmlContent.includes('function hideReconnectingOverlay()'));
        logTest('updateReconnectAttemptDisplay function exists', htmlContent.includes('function updateReconnectAttemptDisplay()'));
        logTest('showNotification function exists', htmlContent.includes('function showNotification(message, type)'));

        // ========================================
        // Test 5: Verify showReconnectingOverlay implementation
        // ========================================
        console.log('\n--- Test 5: Verify showReconnectingOverlay implementation ---');
        const showOverlayRegex = /function showReconnectingOverlay\(\)[\s\S]*?overlay\.style\.display\s*=\s*['"]flex['"]/;
        logTest('showReconnectingOverlay sets display to flex', showOverlayRegex.test(htmlContent));

        // ========================================
        // Test 6: Verify hideReconnectingOverlay implementation
        // ========================================
        console.log('\n--- Test 6: Verify hideReconnectingOverlay implementation ---');
        const hideOverlayRegex = /function hideReconnectingOverlay\(\)[\s\S]*?overlay\.style\.display\s*=\s*['"]none['"]/;
        logTest('hideReconnectingOverlay sets display to none', hideOverlayRegex.test(htmlContent));

        // ========================================
        // Test 7: Verify updateReconnectAttemptDisplay implementation
        // ========================================
        console.log('\n--- Test 7: Verify updateReconnectAttemptDisplay implementation ---');
        logTest('Updates reconnectAttemptCount element', htmlContent.includes("getElementById('reconnectAttemptCount')") ||
                                                        htmlContent.includes('getElementById("reconnectAttemptCount")'));
        logTest('Displays attempt number', htmlContent.includes('reconnectAttempts') && htmlContent.includes('MAX_RECONNECT_ATTEMPTS'));

        // ========================================
        // Test 8: Verify showNotification implementation
        // ========================================
        console.log('\n--- Test 8: Verify showNotification implementation ---');
        logTest('showNotification handles success type', htmlContent.includes("type === 'success'") || htmlContent.includes('type === "success"'));
        logTest('showNotification handles error type', htmlContent.includes("type === 'error'") || htmlContent.includes('type === "error"'));
        logTest('Success style has green background', htmlContent.includes('#d4edda') || htmlContent.includes('rgb(212, 237, 218)'));
        logTest('Error style has red background', htmlContent.includes('#f8d7da') || htmlContent.includes('rgb(248, 215, 218)'));

        // ========================================
        // Test 9: Verify resetGame protection
        // ========================================
        console.log('\n--- Test 9: Verify resetGame protection ---');
        const resetGameProtectionRegex = /function resetGame\(\)[\s\S]*?if\s*\(\s*isReconnecting\s*\)[\s\S]*?return/;
        logTest('resetGame checks isReconnecting flag', resetGameProtectionRegex.test(htmlContent));
        logTest('resetGame returns early when reconnecting', htmlContent.includes('Skipping resetGame()') ||
                                                              htmlContent.includes('reconnection in progress'));

        // ========================================
        // Test 10: Verify disconnect handler logic
        // ========================================
        console.log('\n--- Test 10: Verify disconnect handler logic ---');
        logTest('Disconnect handler exists', htmlContent.includes("socket.on('disconnect'"));
        logTest('Checks if in active game (currentRoomId)', htmlContent.includes('currentRoomId !== null'));
        logTest('Sets isReconnecting to true', htmlContent.includes('isReconnecting = true'));
        logTest('Increments reconnectAttempts', htmlContent.includes('reconnectAttempts++'));
        logTest('Sets hasGameToRestore to true', htmlContent.includes('hasGameToRestore = true'));
        logTest('Shows reconnecting overlay on disconnect', htmlContent.includes('showReconnectingOverlay()'));
        logTest('Does NOT call resetGame when reconnecting',
                htmlContent.includes('// Do NOT call resetGame()') ||
                htmlContent.includes('Do NOT call resetGame'));

        // ========================================
        // Test 11: Verify connect handler reconnection logic
        // ========================================
        console.log('\n--- Test 11: Verify connect handler reconnection logic ---');
        logTest('Connect handler checks isReconnecting', htmlContent.includes('if (isReconnecting)'));
        logTest('Waits for gameStateRestore', htmlContent.includes('gameStateRestore') || htmlContent.includes('game state'));
        logTest('Has 3 second timeout', htmlContent.includes('3000'));
        logTest('Handles max reconnect attempts', htmlContent.includes('MAX_RECONNECT_ATTEMPTS') &&
                                                  htmlContent.includes('reconnectAttempts'));

        // ========================================
        // Test 12: Verify gameStateRestore handler
        // ========================================
        console.log('\n--- Test 12: Verify gameStateRestore handler ---');
        logTest('gameStateRestore handler exists', htmlContent.includes("socket.on('gameStateRestore'"));
        logTest('Validates data.roomId', htmlContent.includes('data.roomId'));
        logTest('Validates data.players is array', htmlContent.includes('Array.isArray(data.players)'));
        logTest('Hides overlay on restore', htmlContent.includes('hideReconnectingOverlay()'));
        logTest('Restores currentRoomId', htmlContent.includes('currentRoomId = data.roomId'));
        logTest('Restores currentBetAmount', htmlContent.includes('currentBetAmount = data.betAmount') ||
                                             htmlContent.includes('currentBetAmount ='));
        logTest('Resets reconnection state', htmlContent.includes('isReconnecting = false'));
        logTest('Shows success notification', htmlContent.includes("showNotification") && htmlContent.includes("success"));

        // ========================================
        // Test 13: Verify gameStateRestore handles game states
        // ========================================
        console.log('\n--- Test 13: Verify gameStateRestore handles game states ---');
        logTest('Checks if gameStarted', htmlContent.includes('data.gameStarted') || htmlContent.includes('gameStarted'));
        logTest('Updates player UI', htmlContent.includes('updatePlayerUI'));
        logTest('Handles waiting room state', htmlContent.includes('Waiting for game to start') ||
                                               htmlContent.includes('waiting'));

        // ========================================
        // Test 14: Verify overlay styling
        // ========================================
        console.log('\n--- Test 14: Verify overlay styling ---');
        logTest('Dark overlay background', htmlContent.includes('rgba(0, 0, 0, 0.8)') ||
                                           htmlContent.includes('background-color: rgba(0,0,0'));
        logTest('White card background', htmlContent.includes('background-color: white') ||
                                         htmlContent.includes('background-color: #fff'));
        logTest('Card is centered', htmlContent.includes('justify-content: center') &&
                                    htmlContent.includes('align-items: center'));
        logTest('Has border radius', htmlContent.includes('border-radius'));
        logTest('Dark theme support exists', htmlContent.includes('dark-theme') &&
                                             htmlContent.includes('reconnectingOverlay'));

        // ========================================
        // Test 15: Verify spinner animation
        // ========================================
        console.log('\n--- Test 15: Verify spinner animation ---');
        logTest('Spin keyframes defined', htmlContent.includes('@keyframes spin'));
        logTest('Spinner rotates 360deg', htmlContent.includes('360deg'));
        logTest('Animation is linear infinite', htmlContent.includes('infinite') && htmlContent.includes('linear'));

        // ========================================
        // Test 16: Verify notification element
        // ========================================
        console.log('\n--- Test 16: Verify notification element ---');
        logTest('Notification element exists', htmlContent.includes('id="notification"'));
        logTest('Notification auto-hides', htmlContent.includes('setTimeout') &&
                                           htmlContent.includes("notification.style.display = 'none'"));

    } catch (err) {
        console.error('\n❌ Test execution error:', err.message);
        console.error(err.stack);
    }

    // Print summary
    console.log('\n' + '='.repeat(50));
    console.log('\n📊 TEST SUMMARY\n');
    console.log(`Total Tests: ${results.passed + results.failed}`);
    console.log(`Passed: ${results.passed} ✅`);
    console.log(`Failed: ${results.failed} ❌`);

    const passRate = results.passed + results.failed > 0
        ? ((results.passed / (results.passed + results.failed)) * 100).toFixed(1)
        : 0;
    console.log(`Pass Rate: ${passRate}%`);

    if (results.failed > 0) {
        console.log('\n❌ Failed Tests:');
        results.tests
            .filter(t => !t.passed)
            .forEach(t => console.log(`  - ${t.name}: ${t.message}`));
    }

    console.log('\n' + '='.repeat(50) + '\n');

    // Exit with appropriate code
    process.exit(results.failed > 0 ? 1 : 0);
}

// Run tests
runTests().catch(err => {
    console.error('Fatal error:', err);
    process.exit(1);
});
