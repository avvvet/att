# ATT

Your immediate encryption and decryption tool. How does it work? You run this binary in any folder, and immediately all files inside that folder will be encrypted.

## First!!

You need to generate a random 32-byte key and keep it external and private. (Warning: make sure to keep it safe, perhaps email it to yourself).

Run `att -k` to generate a 32-byte key in hexadecimal format.

## Encryption

To encrypt your files, place the `att` binary in the folder where your files are located. 
Run `att -e <key>`. All your files will be encrypted immediately.

## Decryption

To decrypt your files, run `att -d <key>`. All your previously encrypted files will be decrypted.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.



