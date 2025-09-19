// Test script to verify dependencies are working
console.log('Testing dependencies...');

try {
  require('dotenv');
  console.log('✅ dotenv loaded successfully');
} catch (error) {
  console.error('❌ dotenv failed to load:', error.message);
}

try {
  require('express');
  console.log('✅ express loaded successfully');
} catch (error) {
  console.error('❌ express failed to load:', error.message);
}

try {
  require('firebase-admin');
  console.log('✅ firebase-admin loaded successfully');
} catch (error) {
  console.error('❌ firebase-admin failed to load:', error.message);
}

console.log('Dependency test complete');
