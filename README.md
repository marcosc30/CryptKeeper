# Password Manager

## Description:
Password Manager is a project I built in Rust. At first, it mainly started as a way of learning Rust, but I'm very glad I did it because it allowed me to expand the project and add features that would be somewhat unfeasible in other languages because of speed. 

I'm still working on pushing the project further, my main ideas to expand are to add cloud SQL storage, add a mobile or web version, add account lockouts (this is somewhat integrated into the code already but is not turned on yet), and integrate checking for if a password has been featured in a leak (that last one is limited by the haveIbeenpwned API costing money, I might look for alternatives in the future).

## Features:
- Secure password storage using AES encryption in CBC mode with a keysize of 256, so essentially impenetrable (I may increase key size in the future to make it overkill)
- Password strength detection which takes into account the list of 100k most common passwords (may be expanded to 1m in the future as a feature)
- Easy-to-use GUI to see passwords, as well as adding, editing, and deleting passwords/accounts/websites triplets
- Search functionality to quickly find accounts

## Installation:
- If you just want to run it, click on the Download folder in the repository and download just that from github
- If you want to make modifications or look through the code, clone the repository as you would normally

## Usage:
1. Launch the Password Manager application.
2. Create a new account or log in with an existing account.
3. Add your passwords by providing the necessary details.
4. Use the search functionality to find specific passwords.
5. Edit or delete passwords as needed.

Until cloud support is directly integrated, I recommend backing up passwords.

Keep that master password safe!! No matter who encrypted everything is, if you have the password, it's wraps. I may add MFA to it in the future to prevent harmful attacks, but since this is not available on the web, an attacker must have both the password and access to the device or the database files, which is a similar level of penetration to being able to beat MFA anyway.

