/***********
This is a workaround for this issue: https://github.com/vitejs/vite/issues/8427
Actually, I’m not even sure we are really working around the exact same issue.
Indeed, this dance is only required when bundling using vite 5, but wasn’t required when using vite 4.
***********/

import { readFile, writeFile } from "fs";
import path from "path";
import { fileURLToPath } from 'url';

const rootDir = path.dirname(fileURLToPath(import.meta.url));
const preBundledPickyJs = path.join(rootDir, './dist/picky.js');

readFile(preBundledPickyJs, 'utf8', (err, data) => {
    if (err) {
        console.error('Error reading the file:', err);
        return;
    }

    // Replace all instances of 'import.meta.url' with 'self.location'.
    const modifiedData = data.replace(/import\.meta\.url/g, 'self.location');

    // Write the modified content back to the file.
    writeFile(preBundledPickyJs, modifiedData, 'utf8', (err) => {
        if (err) {
            console.error('Error writing to the file:', err);
            return;
        }

        console.log('File has been modified successfully.');
    });
});

