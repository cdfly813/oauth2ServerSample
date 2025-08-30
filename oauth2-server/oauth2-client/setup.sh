#!/bin/bash

echo "🚀 OAuth2 Client Setup Script"
echo "============================="

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js first."
    echo "   Visit: https://nodejs.org/"
    exit 1
fi

# Check Node.js version
NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 16 ]; then
    echo "❌ Node.js version 16 or higher is required. Current version: $(node -v)"
    exit 1
fi

echo "✅ Node.js version: $(node -v)"
echo "✅ npm version: $(npm -v)"

# Install dependencies
echo ""
echo "📦 Installing dependencies..."
npm install

if [ $? -eq 0 ]; then
    echo "✅ Dependencies installed successfully!"
else
    echo "❌ Failed to install dependencies"
    exit 1
fi

# Create .env file for configuration
echo ""
echo "⚙️  Creating environment configuration..."

cat > .env << EOF
# OAuth2 Server Configuration
REACT_APP_OAUTH2_SERVER_URL=http://localhost:8080
REACT_APP_CLIENT_ID=client1
REACT_APP_CLIENT_SECRET=secret
EOF

echo "✅ Configuration file created"

# Display setup instructions
echo ""
echo "🎉 Setup Complete!"
echo "=================="
echo ""
echo "To start the OAuth2 client:"
echo "1. Make sure your OAuth2 server is running on http://localhost:8080"
echo "2. Run: npm start"
echo "3. Open http://localhost:3000 in your browser"
echo ""
echo "Test Credentials:"
echo "- Admin: username=admin, password=admin"
echo "- User: username=testuser, password=password"
echo ""
echo "Happy coding! 🎊"
