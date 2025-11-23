const bcrypt = require('bcrypt');

async function generatePasswordHash(password) {
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    console.log('=== Password Hash for: ' + password + ' ===');
    console.log(hashedPassword);
    console.log('==========================================');
}

generatePasswordHash('8520');