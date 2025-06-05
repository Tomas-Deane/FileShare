# FileShare

**CS4455 – EPIC**  
**EPIC FileShare Project**


## Team

- **Network Risk Mitigation Corp**  
  - Dara Heaphy (23369914)  
  - Tomas Deane  (23363258)
  - Naem Haq (23379243)  
  - Tiernan Scully (23365528)  
  - Daniel Moody   (23370157)

## Overview

FileShare is a secure, end-to-end encrypted file-sharing platform with both a Qt desktop client and a JavaScript web client. It emphasises confidentiality, integrity and authenticity, even if the server or network is compromised.



## Architecture & Modules

- **Backend Server**  
  - Exposes a RESTful API for authentication, file management and sharing.  
  - Implemented in REACT typescript.

- **Qt Client (C++)**  
  - Native desktop application.  
  - Demonstrates modern C++ features (OOP, templates, smart pointers, etc.)

- **Web Client (JavaScript)**  
  - Browser-based SPA.  
  - Uses Web Crypto API and up-to-date security headers.

## Instalation instructions

### npm project 

1. **Prerequisites**
   - Node.js (v16 or higher)
   - npm (v7 or higher)

2. **Installation**
   ```bash
   # Navigate to the web client directory
   cd fileshareweb

   # Install dependencies
   npm install
   ```

3. **Configuration**
   - Create a `.env` file in the `fileshareweb` directory with the following variables:
     ```
     REACT_APP_API_URL=http://localhost:3000
     REACT_APP_WS_URL=ws://localhost:8000
     ```

4. **Running the Development Server**
   ```bash
   # Start the development server
   npm run start:https
   ```
   The application will be available at `http://localhost:3000`

5. **Building for Production**
   ```bash
   # Create a production build
   npm run build
   ```
   The build output will be in the `build` directory

6. **Running Tests**
   ```bash
   # Run the test suite
   npm test
   ```

7. **Troubleshooting**
   - If you encounter SSL certificate issues, ensure the certificates are properly placed in the `ssl` directory
   - For dependency issues, try clearing the npm cache:
     ```bash
     npm cache clean --force
     rm -rf node_modules
     npm install
     ```

### Qt Project

1. **Prerequisites**
   - Qt 6.9 or higher
   - QMake 3.16 or higher
   - C++ compiler (MSVC, GCC, or Clang)
   - OpenSSL development libraries

2. **Installation**
   ```bash
   # Navigate to the Qt client directory
   cd fileshareqt

   # Create build directory
   mkdir build
   cd build

   # Configure the project
   cmake ..

   # Build the project
   cmake --build .
   ```

3. **Configuration**
   - SSL certificates should be placed in the `ssl` directory:
     - `client.crt` - Client certificate
     - `client.key` - Client private key
     - `ca.crt` - CA certificate

4. **Running the Application**
   ```bash
   # From the build directory
   ./FileShareQt
   ```

5. **Development with Qt Creator**
   - Open `fileshareqt.pro` in Qt Creator
   - Configure the project with your preferred kit
   - Build and run directly from Qt Creator

6. **Troubleshooting**
   - If SSL certificate errors occur:
     - Verify certificate paths in the application
     - Ensure certificates are in the correct format
   - For build errors:
     - Check Qt and CMake versions
     - Verify all dependencies are installed
     - Clean build directory and rebuild:
       ```bash
       rm -rf build/*
       cmake ..
       cmake --build .
       ```

7. **Project Structure**
   - `controllers/` - Business logic and API communication
   - `models/` - Data models and structures
   - `views/` - UI components and layouts
   - `utils/` - Utility functions and helpers
   - `styles/` - Application styling and themes
