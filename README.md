Overview (University Project - Individual)
  - This project is made to implement a simplified and highy insecure version of RSA.
  - The project is for digital signatures instead of encrypted key-sharing
  - The project will take input from standard input; either "sign" or "verify" mode.
  - Sign mode - this mode will sign a input message from standard input. The program will hash the message using ELFhash. The 32-bit resulting number will be then encrypted to get the digital signature.
  - Verify mode - this mode will verify is a signature matches a hash computed.
