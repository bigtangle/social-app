read example/hdwallet.ts
add generate wallet file with key to 
save and load file 

 
1. register of public key and other data in pds (local or in bigtangle blockchain)
2. login with the public key
3. send the public key to pds
4. pds send a random onetime secret using the public key to client
5. client encrypt the message and send the  onetime secret as password to 
 

 
add Create Account with hd public key for signin using bitcoin-libs in bluesky social-app and pds#

The user wants to add HD wallet-based authentication using Bitcoin libraries to the Bluesky social-app. Based on the current file structure and previous context, I'll need to:

1. First install required Bitcoin libraries
2. Create HD wallet utility functions
3. Add a new authentication method to the auth service
4. Create UI components for wallet-based login
5. Update type definitions

I'll proceed step by step, starting with installing dependencies and creating core functionality before moving to UI integration.
