# PII Detection Chrome Extension

A Chrome extension that detects and highlights Personally Identifiable Information (PII) on web pages using Microsoft Presidio Analyzer, with click-to-redact functionality.

## Features

- **Real PII Detection**: Uses Microsoft Presidio Analyzer backend for accurate PII detection
- **Universal PII Detection**: Works on Google Docs, ChatGPT, Gmail, and other web pages
- **Real-time Highlighting**: Highlights detected PII with yellow backgrounds
- **Click-to-Redact**: Click highlighted text to review and redact PII
- **Overlay System**: Fallback highlighting for protected content areas
- **Multiple Detection Types**: 
  - Names (PERSON)
  - Locations (LOCATION) 
  - Phone numbers (PHONE)
  - Email addresses (EMAIL)
  - Credit cards, SSN, IP addresses, and more

## Prerequisites

- Python 3.8 or higher
- Chrome browser
- pip (Python package manager)

## Backend Setup

The extension requires a Flask backend server running Presidio Analyzer.

### 1. Install Python Dependencies

```bash
# Install required Python packages
pip install -r requirements.txt

# Download spaCy English language model (required by Presidio)
python -m spacy download en_core_web_lg
```

**Note**: The `en_core_web_lg` model is large (~500MB). If you prefer a smaller model, you can use `en_core_web_sm` instead, but detection accuracy may be slightly lower.

### 2. Start the Backend Server

```bash
# Run the Flask server
python app.py
```

The server will start on `http://127.0.0.1:5000` by default.

You should see output like:
```
🚀 Starting fresh Presidio PII detection...
📝 Initializing Presidio...
✅ Presidio Analyzer initialized successfully
Starting PII Detection API server on 127.0.0.1:5000
```

### 3. Verify Backend is Running

Open your browser and visit:
- `http://127.0.0.1:5000/health` - Should return `{"status": "healthy", "presidio_initialized": true}`
- `http://127.0.0.1:5000/` - Should show API information

## Chrome Extension Installation

1. Download or clone this repository
2. Open Chrome and go to `chrome://extensions/`
3. Enable "Developer mode" in the top right
4. Click "Load unpacked" and select the extension folder
5. The extension will appear in your extensions list

**Important**: Make sure the backend server is running before using the extension!

## Usage

1. **Start the backend server** (see Backend Setup above)
2. Navigate to any supported webpage (Google Docs, ChatGPT, etc.)
3. Look for the "🛡️ Scan for PII" button in the top-right corner
4. Click the button to scan for PII
5. Yellow highlights will appear over detected PII
6. Click any highlighted text to review and accept/reject the PII suggestion
7. Use "✅ Accept All" to automatically redact all detected PII
8. Use "❌ Clear Highlights" to remove all highlights

### Backend Connection

- If the backend is running, the extension will use Presidio for real PII detection
- If the backend is unavailable, the extension will fall back to mock data and show a warning
- Check the browser console (F12) for connection status and errors

## Supported Websites

- ✅ Google Docs
- ✅ ChatGPT (chat.openai.com, chatgpt.com)
- ✅ Gmail
- ✅ Most standard websites

## Project Structure

### Chrome Extension Files
- `manifest.json` - Extension configuration and permissions
- `content.js` - Main detection and highlighting logic, API integration
- `style.css` - Styling for buttons and highlights

### Backend Files
- `app.py` - Flask backend server with Presidio Analyzer integration
- `requirements.txt` - Python dependencies
- `sample_pii_detector.py` - Sample Presidio code (reference)

### Documentation
- `README.md` - This documentation

## Technical Details

### Backend API

The Flask backend provides a REST API endpoint:

- **POST `/detect-pii`**: Analyzes text for PII
  - Request body: `{"text": "text to analyze", "language": "en", "model": "presidio"}`
  - Response: `{"has_pii": true, "detected_entities": [...], "total_entities": 5, ...}`

- **GET `/health`**: Health check endpoint

### Extension Architecture

The extension uses two highlighting methods:

1. **Direct HTML Modification**: For most websites, directly modifies the DOM
2. **Overlay System**: For protected content (like ChatGPT), creates floating highlights

### PII Detection

The extension uses **Microsoft Presidio Analyzer** for PII detection, which can identify:
- Person names
- Email addresses
- Phone numbers
- Locations
- Credit card numbers
- Social Security Numbers (SSN)
- IP addresses
- URLs
- Dates and times
- And more...

### Fallback Mode

If the backend server is unavailable, the extension will:
- Show a warning message
- Fall back to mock data for testing
- Continue to function (with limited detection)

## Configuration

### Changing Backend URL

To use a different backend URL, edit `content.js`:

```javascript
const BACKEND_API_URL = 'http://your-backend-url:port/detect-pii';
const BACKEND_HEALTH_URL = 'http://your-backend-url:port/health';
```

### Backend Server Configuration

To change the backend port or host, set environment variables:

```bash
export HOST=0.0.0.0  # Listen on all interfaces
export PORT=8080     # Use port 8080
python app.py
```

## Troubleshooting

### Backend not connecting

1. Verify the backend server is running: `curl http://127.0.0.1:5000/health`
2. Check browser console (F12) for CORS or connection errors
3. Ensure `manifest.json` includes the correct backend URL in `host_permissions`
4. Try accessing the backend URL directly in your browser

### Presidio initialization errors

1. Ensure spaCy model is installed: `python -m spacy download en_core_web_lg`
2. Check Python version: `python --version` (should be 3.8+)
3. Reinstall dependencies: `pip install -r requirements.txt --force-reinstall`

### Extension not loading

1. Check Chrome extension error page: `chrome://extensions/`
2. Reload the extension after making changes
3. Ensure all files are in the same directory

## License

MIT License